package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)


const (
	time3600 = time.Hour
	millis   = time.Millisecond
)

func nowFn() time.Time { return time.Now() }

func TestValidateManagedPathAllowsOnlyManagedLocations(t *testing.T) {
	allowed := []string{
		"/etc/dnsmasq.d/softrouter-dhcp.conf",
		"/etc/wireguard/wg0.conf",
		"/etc/openvpn/client/pia.conf",
		"/etc/openvpn/easy-rsa/pki/ca.crt",
		"/etc/frr/frr.conf",
		"/etc/miniupnpd/miniupnpd.conf",
		"/etc/suricata/modify.conf",
		"/etc/systemd/resolved.conf.d/softrouter-dns-privacy.conf",
		"/etc/systemd/system/suricata.service.d/override.conf",
		"/etc/nftables.conf",
		"/etc/nftables.conf.backup",
		"/etc/radvd.conf",
	}
	for _, path := range allowed {
		if err := validateManagedPath(path, false); err != nil {
			t.Errorf("expected %s to be allowed, got %v", path, err)
		}
	}

	denied := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/ssh/sshd_config",
		"/etc/dnsmasq.d/evil.sh",
		"/etc/wireguard/evil.sh",
		"/etc/systemd/resolved.conf.d/other.conf",
		"/etc/systemd/system/suricata.service.d/other.conf",
		"/run/softrouter-priv/priv.sock",
		"/run/softrouter-priv/anything",
		"/run/softrouter/tmp/fallback-dnsmasq.conf",
		"relative/path",
		"/etc/dnsmasq.d/../passwd",
	}
	for _, path := range denied {
		if err := validateManagedPath(path, false); err == nil {
			t.Errorf("expected %s to be denied", path)
		}
	}
}

func TestManagedReadPathAllowsOnlyPKIFiles(t *testing.T) {
	allowed := []string{
		"/etc/openvpn/server/ca.crt",
		"/etc/openvpn/server/ta.key",
		"/etc/openvpn/server/crl.pem",
		"/etc/openvpn/easy-rsa/pki/index.txt",
		"/etc/openvpn/easy-rsa/pki/issued/client1.crt",
		"/etc/openvpn/easy-rsa/pki/private/client1.key",
	}
	for _, path := range allowed {
		if err := validateManagedReadPath(path); err != nil {
			t.Errorf("expected %s to be readable, got %v", path, err)
		}
	}

	denied := []string{
		"/etc/shadow",
		"/etc/openvpn/server/server.key",
		"/etc/openvpn/easy-rsa/pki/private/server.key",
		"/etc/openvpn/easy-rsa/pki/private/ca.key",
		"/etc/openvpn/easy-rsa/pki/issued/server.crt",
		"/etc/openvpn/easy-rsa/easyrsa",
		"/etc/openvpn/easy-rsa/pki/issued/../private/server.key",
		"/etc/openvpn/easy-rsa/pki/issued/foo/bar.crt",
		"/etc/openvpn/easy-rsa/pki/issued/client1.conf",
		"relative/path",
	}
	for _, path := range denied {
		if err := validateManagedReadPath(path); err == nil {
			t.Errorf("expected %s to be denied", path)
		}
	}
}

func TestValidateDnsmasqConfRejectsDangerousDirectives(t *testing.T) {
	good := "port=0\ndhcp-authoritative\ndhcp-range=192.168.1.10,192.168.1.100,12h\n"
	if err := validateDnsmasqConf(good); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}

	bad := []string{
		"dhcp-script=/bin/sh",
		"dhcp-luascript=/tmp/evil.lua",
		"script-on-renewal",
		"lua-script=/tmp/evil.lua",
		"conf-file=/etc/passwd",
		"conf-dir=/etc",
		"servers-file=/tmp/x",
		"log-facility=/etc/passwd",
	}
	for _, line := range bad {
		if err := validateDnsmasqConf(line); err == nil {
			t.Errorf("expected dnsmasq directive to be rejected: %s", line)
		}
	}
}

func TestValidateWireGuardConfRejectsHooks(t *testing.T) {
	good := `[Interface]
PrivateKey = abc=
Address = 10.8.0.1/24
PostUp = nft add table inet wg-filter
PostUp = nft add rule inet wg-filter postrouting iifname "wg0" oifname != "wg0" masquerade
PostDown = nft delete table inet wg-filter
`
	if err := validateWireGuardConf(good); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}

	bad := []string{
		wgBlanketMasqueradePostUp, // legacy rule with no interface match
		"PostUp = /bin/sh -c id",
		"PostDown = curl https://example.com",
		"PreUp = /tmp/evil",
	}
	for _, line := range bad {
		if err := validateWireGuardConf(line); err == nil {
			t.Errorf("expected WireGuard hook to be rejected: %s", line)
		}
	}
}

func TestValidateOpenVPNFile(t *testing.T) {
	server := `port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-crypt ta.key
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
`
	if err := validateOpenVPNFile("/etc/openvpn/server/server.conf", server); err != nil {
		t.Fatalf("valid server config rejected: %v", err)
	}

	bad := []string{
		"plugin /tmp/evil.so",
		"script-security 2",
		"up /tmp/evil.sh",
		"status /etc/shadow",
		"log ../../etc/passwd",
		"config /etc/openvpn/evil.conf",
		"management 127.0.0.1 9999",
	}
	for _, line := range bad {
		if err := validateOpenVPNFile("/etc/openvpn/server/server.conf", line); err == nil {
			t.Errorf("expected OpenVPN directive to be rejected: %s", line)
		}
	}

	// Non-.conf files (keys, auth files) are not parsed as configs.
	if err := validateOpenVPNFile("/etc/openvpn/client/pia.auth", "user\npass\n"); err != nil {
		t.Fatalf("auth file rejected: %v", err)
	}
}


func TestHelperAcceptsTheWireGuardConfigTheBackendGenerates(t *testing.T) {
	if err := validateWireGuardConf(wireGuardBaseConf("PRIVATEKEY=")); err != nil {
		t.Fatalf("helper would reject the backend's own wg0.conf: %v", err)
	}
}

func TestEasyRSAClientNames(t *testing.T) {
	for _, ok := range []string{"client1", "my-phone", "Laptop_2"} {
		if !validEasyRSAClientName(ok) {
			t.Errorf("%q should be a valid client name", ok)
		}
	}
	for _, bad := range []string{"server", "ca", "", "../x", "a/b", "a b", "x.crt"} {
		if validEasyRSAClientName(bad) {
			t.Errorf("%q must not be a valid client name", bad)
		}
	}
}

func TestLimitedBufferCapsOutput(t *testing.T) {
	b := &limitedBuffer{max: 10}
	n, err := b.Write([]byte("0123456789ABCDEF"))
	if n != 16 || err != nil {
		t.Fatalf("Write must report all bytes consumed, got %d %v", n, err)
	}
	b.Write([]byte("more"))
	if b.buf.String() != "0123456789" {
		t.Errorf("buffer = %q", b.buf.String())
	}
}

// serveFakeHelper answers requests on a temporary socket and records them.
func serveFakeHelper(t *testing.T, reply PrivResponse) (requests chan PrivRequest) {
	t.Helper()
	old, oldAt := privSocketPath, helperProbeAt
	t.Cleanup(func() { privSocketPath, helperProbeAt = old, oldAt })
	privSocketPath = filepath.Join(t.TempDir(), "p.sock")
	helperProbeAt = helperProbeAt.Add(-time3600) // force a fresh probe
	ln, err := net.Listen("unix", privSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	requests = make(chan PrivRequest, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req PrivRequest
			json.NewDecoder(c).Decode(&req)
			requests <- req
			json.NewEncoder(c).Encode(reply)
			c.Close()
		}
	}()
	return requests
}

func TestExecutorUsesTheHelperWhenItIsRunning(t *testing.T) {
	reqs := serveFakeHelper(t, PrivResponse{Stdout: "from helper"})

	out, err := runPrivilegedOutput("ip", "addr", "show", "lo")
	if err != nil || string(out) != "from helper" {
		t.Fatalf("expected the helper's output, got %q %v", out, err)
	}
	r := <-reqs
	if r.Op != "exec" || r.Command != "ip" || strings.Join(r.Args, " ") != "addr show lo" || r.Combined {
		t.Errorf("unexpected request: %+v", r)
	}

	if _, err := runPrivilegedCombinedOutput("ip", "addr", "show", "lo"); err != nil {
		t.Fatal(err)
	}
	if r := <-reqs; !r.Combined {
		t.Error("combined output must be requested from the helper")
	}

	if err := runPrivilegedInDir("/etc/openvpn/easy-rsa", "openvpn", "--genkey", "--secret", "ta.key"); err != nil {
		t.Fatal(err)
	}
	if r := <-reqs; r.Dir != "/etc/openvpn/easy-rsa" {
		t.Errorf("working directory not forwarded: %+v", r)
	}

	if _, err := runPrivilegedWithStdin([]byte("secret"), "ip", "addr", "show", "lo"); err != nil {
		t.Fatal(err)
	}
	if r := <-reqs; string(r.Stdin) != "secret" {
		t.Errorf("stdin not forwarded: %+v", r)
	}
}

func TestExecutorReportsHelperFailuresAndDoesNotRetryLocally(t *testing.T) {
	reqs := serveFakeHelper(t, PrivResponse{ExitCode: 3, Stderr: "boom"})
	err := runPrivileged("ip", "addr", "show", "lo")
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the helper's failure, got %v", err)
	}
	<-reqs
	select {
	case extra := <-reqs:
		t.Errorf("a failed command must not be sent twice: %+v", extra)
	default:
	}
}

func TestExecutorRejectsDisallowedCommandsBeforeContactingTheHelper(t *testing.T) {
	reqs := serveFakeHelper(t, PrivResponse{})
	if err := runPrivileged("cat", "/etc/shadow"); err == nil {
		t.Fatal("disallowed command must be rejected")
	}
	select {
	case r := <-reqs:
		t.Errorf("the helper must not be asked to run a disallowed command: %+v", r)
	default:
	}
}

func TestMissingOrDeadHelperIsNotAvailableAndNeverDelays(t *testing.T) {
	old, oldAt := privSocketPath, helperProbeAt
	defer func() { privSocketPath, helperProbeAt = old, oldAt }()

	dir := t.TempDir()
	privSocketPath = filepath.Join(dir, "missing.sock")
	helperProbeAt = helperProbeAt.Add(-time3600)
	start := nowFn()
	if privHelperAvailable() {
		t.Fatal("no socket means no helper")
	}
	if d := nowFn().Sub(start); d > 200*millis {
		t.Errorf("probing a missing helper took %v; it must not sleep or retry", d)
	}

	// A stale socket file with nobody listening: connecting fails, so fall back locally.
	stale := filepath.Join(dir, "stale.sock")
	ln, _ := net.Listen("unix", stale)
	ln.Close() // leaves the file behind on some systems; make sure it exists
	os.WriteFile(stale, nil, 0600)
	privSocketPath = stale
	helperProbeAt = helperProbeAt.Add(-time3600)
	if _, err, used := tryHelperExec("", nil, false, "ip", "addr"); used || err != nil {
		t.Errorf("an unreachable helper must fall back to local execution: used=%v err=%v", used, err)
	}
	if _, err := runViaHelperRequest(PrivRequest{Op: "exec"}); !errors.Is(err, errHelperUnreachable) {
		t.Errorf("connect failures must be reported as errHelperUnreachable, got %v", err)
	}
}
