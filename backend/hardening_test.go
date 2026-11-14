package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestOpenVPNAllowlistRejectsDangerous(t *testing.T) {
	bad := []string{
		"plugin /tmp/evil.so", "up /tmp/x.sh", "down /tmp/x.sh", "route-up /bin/sh",
		"auth-user-pass-verify /x via-env", "tls-verify /x", "script-security 2",
		"setenv FOO bar", "config /etc/shadow", "management 127.0.0.1 7505", "daemon",
		"chroot /", "writepid /etc/x", "log /tmp/l", "status /tmp/s", "askpass /etc/shadow",
		"ipchange /x", "learn-address /x", "client-connect /x",
		"remote evil.com;id 1194", "remote host 99999", "ca /etc/shadow", "cert ../../etc/passwd",
		"key relative.key", "<plugin>\nfoo\n</plugin>", "totally-unknown-directive 1",
	}
	for _, b := range bad {
		if _, err := sanitizeOpenVPNConfig("client\n" + b + "\n"); err == nil {
			t.Errorf("expected rejection for %q", b)
		}
	}
	if _, err := sanitizeOpenVPNConfig("client\x00\nremote a.b 1194\n"); err == nil {
		t.Error("NUL byte must be rejected")
	}
	if _, err := sanitizeOpenVPNConfig(strings.Repeat("#", maxOVPNConfigSize+1)); err == nil {
		t.Error("oversize file must be rejected")
	}
	if _, err := sanitizeOpenVPNConfig("<ca>\nAAAA\nid; rm -rf /\n</ca>\n"); err == nil {
		t.Error("illegal chars inside inline block must be rejected")
	}
}

func TestOpenVPNAllowlistAcceptsTypicalProviderConfig(t *testing.T) {
	cfg := `client
dev tun
proto udp
remote us-east.example.com 1198
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-128-cbc
auth sha1
tls-client
remote-cert-tls server
auth-user-pass
compress
verb 1
<ca>
-----BEGIN CERTIFICATE-----
MIIDsTCCAxqgAwIBAgIJAL
-----END CERTIFICATE-----
</ca>
`
	out, err := sanitizeOpenVPNConfig(cfg)
	if err != nil {
		t.Fatalf("typical config rejected: %v", err)
	}
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "dev tun") || strings.Contains(joined, "auth-user-pass") {
		t.Error("dev/auth-user-pass must be stripped (installer injects its own)")
	}
}

func TestSanitizeNFTValue(t *testing.T) {
	for _, bad := range []string{`eth0" accept`, "a\nb", "a;b", "a{b", "a}b", "a#b", `a\b`, "a\x00b", ""} {
		if sanitizeNFTValue(bad) == nil {
			t.Errorf("expected %q rejected", bad)
		}
	}
	if sanitizeNFTValue("eth0") != nil || sanitizeNFTValue("br-lan.10") != nil {
		t.Error("valid names rejected")
	}
}

func TestValidateMAC(t *testing.T) {
	if m, err := validateMAC("AA:BB:CC:DD:EE:FF"); err != nil || m != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("got %q %v", m, err)
	}
	for _, bad := range []string{"aa:bb:cc:dd:ee:ff drop; accept", "zz:bb:cc:dd:ee:ff", "", "aa:bb:cc:dd:ee:ff:00:11"} {
		if _, err := validateMAC(bad); err == nil {
			t.Errorf("expected %q rejected", bad)
		}
	}
}

func testCfg(mod func(*Config)) Config {
	c := Config{FirewallEnabled: true, ProtectedSubnet: "192.168.1.0/24"}
	c.TLS.Port = ":443"
	if mod != nil {
		mod(&c)
	}
	return c
}

func TestRulesetWANSSHDNSGating(t *testing.T) {
	fm := &FirewallManager{}
	locked, err := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(locked, "\n") {
		if (strings.Contains(l, "dport 22") || strings.Contains(l, "dport 53")) && !strings.Contains(l, `iifname "br0"`) {
			t.Errorf("unfiltered or WAN SSH/DNS rule present after lockdown: %q", l)
		}
	}
	if strings.Contains(locked, "flush ruleset") {
		t.Error("flush ruleset must not be emitted")
	}
	prov, _ := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(func(c *Config) { c.ProvisioningMode = true }), nil)
	if !strings.Contains(prov, `iifname "eth0" tcp dport 22 accept`) || !strings.Contains(prov, `iifname "eth0" udp dport 53 accept`) {
		t.Error("provisioning mode should open WAN SSH+DNS")
	}
	optin, _ := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(func(c *Config) { c.AllowWANSSH = true }), nil)
	if !strings.Contains(optin, `iifname "eth0" tcp dport 22 accept`) || strings.Contains(optin, `iifname "eth0" tcp dport 53`) {
		t.Error("AllowWANSSH should open only SSH")
	}
}

func TestRulesetRejectsInjection(t *testing.T) {
	fm := &FirewallManager{}
	if _, err := fm.generateFullRuleset([]string{`eth0" accept comment "x`}, []string{"br0"}, testCfg(nil), nil); err == nil {
		t.Error("injected WAN interface name must be rejected")
	}
	if _, err := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(func(c *Config) { c.TLS.Port = ":443 accept" }), nil); err == nil {
		t.Error("non-integer TLS port must be rejected")
	}
	if _, err := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(func(c *Config) { c.ProtectedSubnet = "1.1.1.1\ndrop" }), nil); err == nil {
		t.Error("bad subnet must be rejected")
	}
}

func TestRulesetPassesNftCheck(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	fm := &FirewallManager{}
	for name, mod := range map[string]func(*Config){
		"locked":       nil,
		"provisioning": func(c *Config) { c.ProvisioningMode = true },
		"baseline":     func(c *Config) { c.FirewallEnabled = false },
	} {
		rs, err := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(mod), nil)
		if err != nil {
			t.Fatal(err)
		}
		f, _ := os.CreateTemp("", "chk-*.nft")
		f.WriteString(rs)
		f.Close()
		out, err := exec.Command("nft", "-c", "-f", f.Name()).CombinedOutput()
		os.Remove(f.Name())
		if err != nil {
			t.Errorf("%s ruleset failed nft -c: %v\n%s\n---\n%s", name, err, out, rs)
		}
	}
}
