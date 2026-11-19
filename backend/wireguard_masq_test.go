package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestWireGuardBaseConfHasNoUnscopedMasquerade(t *testing.T) {
	conf := wireGuardBaseConf("PRIVATEKEY=")
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "masquerade") && !strings.Contains(line, `iifname "wg0"`) {
			t.Errorf("masquerade rule without an interface match: %q", line)
		}
		if line == wgBlanketMasqueradePostUp {
			t.Error("base config must not contain the legacy blanket masquerade")
		}
	}
	for _, want := range []string{"PrivateKey = PRIVATEKEY=", "ListenPort = 51820", wgScopedMasqueradePostUp, "PostDown = nft delete table inet wg-filter"} {
		if !strings.Contains(conf, want) {
			t.Errorf("base config missing %q", want)
		}
	}
}

func TestScopeWireGuardMasqueradeMigratesOnlyTheLegacyLine(t *testing.T) {
	legacy := "[Interface]\nPrivateKey = K=\nAddress = 10.8.0.1/24\nPostUp = nft add table inet wg-filter\n" +
		wgBlanketMasqueradePostUp + "\nPostDown = nft delete table inet wg-filter\n\n" +
		"# phone\n[Peer]\nPublicKey = P=\nAllowedIPs = 10.8.0.2/32\n"

	got, changed := scopeWireGuardMasquerade(legacy)
	if !changed {
		t.Fatal("legacy config should be migrated")
	}
	if strings.Contains(got, wgBlanketMasqueradePostUp+"\n") || !strings.Contains(got, wgScopedMasqueradePostUp) {
		t.Errorf("legacy line not replaced:\n%s", got)
	}
	// Peers and every other line survive untouched.
	for _, keep := range []string{"# phone", "[Peer]", "PublicKey = P=", "AllowedIPs = 10.8.0.2/32", "PostDown = nft delete table inet wg-filter"} {
		if !strings.Contains(got, keep) {
			t.Errorf("migration lost %q", keep)
		}
	}
	if strings.Count(got, "\n") != strings.Count(legacy, "\n") {
		t.Error("migration must not add or remove lines")
	}

	// Idempotent, and hand-edited configs are left alone.
	if again, changed := scopeWireGuardMasquerade(got); changed || again != got {
		t.Error("second run must be a no-op")
	}
	custom := "[Interface]\nPostUp = nft add rule inet wg-filter postrouting oifname \"enp3s0f1\" masquerade\n"
	if same, changed := scopeWireGuardMasquerade(custom); changed || same != custom {
		t.Error("a hand-edited masquerade rule must not be rewritten")
	}
}

func TestScopedMasqueradeRuleIsValidNft(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	// wg-quick runs PostUp through the shell, so the quotes are gone by the time nft sees it.
	rule := strings.TrimPrefix(wgScopedMasqueradePostUp, "PostUp = nft add rule inet wg-filter postrouting ")
	rule = strings.ReplaceAll(rule, `"`, "")
	ruleset := "table inet wg-filter {\n chain postrouting {\n  type nat hook postrouting priority 100; policy accept;\n  " + rule + "\n }\n}\n"
	f, _ := os.CreateTemp("", "wg-*.nft")
	f.WriteString(ruleset)
	f.Close()
	defer os.Remove(f.Name())
	if out, err := exec.Command("nft", "-c", "-f", f.Name()).CombinedOutput(); err != nil {
		t.Errorf("scoped rule failed nft -c: %v\n%s", err, out)
	}
}
