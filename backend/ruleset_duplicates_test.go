package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	chainHeaderRe = regexp.MustCompile(`^\s*chain (\S+) \{`)
	commentRe     = regexp.MustCompile(` comment "[^"]*"`)
)

// duplicateRulesIn returns rules that appear more than once in the same chain, ignoring
// comments (this is what the dashboard's firewall cleanup treats as a duplicate).
func duplicateRulesIn(ruleset string) []string {
	var chain string
	seen := map[string]int{}
	var dups []string
	for _, line := range strings.Split(ruleset, "\n") {
		if m := chainHeaderRe.FindStringSubmatch(line); m != nil {
			chain = m[1]
			continue
		}
		rule := strings.TrimSpace(commentRe.ReplaceAllString(line, ""))
		if chain == "" || rule == "" || rule == "}" || strings.HasPrefix(rule, "type ") {
			continue
		}
		key := chain + ": " + rule
		seen[key]++
		if seen[key] == 2 {
			dups = append(dups, key)
		}
	}
	return dups
}

func TestRulesetHasNoDuplicateRulesWhenWireGuardIsUp(t *testing.T) {
	old := wgConfPath
	defer func() { wgConfPath = old }()
	wgConfPath = filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(wgConfPath, []byte("[Interface]\n"), 0600); err != nil {
		t.Fatal(err)
	}

	fm := &FirewallManager{}
	// wg0 exists, so the interface scan counts it as a LAN interface as well.
	rs, err := fm.generateFullRulesetGuest(
		[]string{"eth0", "eth1"}, []string{"br0", "wg0"}, []string{"eth2.20"}, nil, testCfg(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if dups := duplicateRulesIn(rs); len(dups) != 0 {
		t.Errorf("generated ruleset contains duplicate rules: %v", dups)
	}
	if n := strings.Count(rs, `iifname "wg0" accept comment "WireGuard peers (trusted)"`); n != 1 {
		t.Errorf("expected the WireGuard trust rule exactly once, got %d", n)
	}
	if strings.Contains(rs, `iifname "wg0" accept comment "LAN trust"`) {
		t.Error("wg0 must not also get a second trust rule from the LAN loop")
	}
}

func TestWireGuardStillTrustedWhenNoServerConfigExists(t *testing.T) {
	old := wgConfPath
	defer func() { wgConfPath = old }()
	wgConfPath = filepath.Join(t.TempDir(), "missing-wg0.conf") // WireGuard not configured

	fm := &FirewallManager{}
	rs, err := fm.generateFullRulesetGuest(
		[]string{"eth0"}, []string{"br0", "wg0"}, nil, nil, testCfg(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Without a server config the dedicated rule is not written, so the LAN rule must stay.
	if n := strings.Count(rs, `iifname "wg0" accept comment "LAN trust"`); n != 1 {
		t.Errorf("expected one LAN trust rule for an existing wg0, got %d", n)
	}
	if dups := duplicateRulesIn(rs); len(dups) != 0 {
		t.Errorf("duplicate rules: %v", dups)
	}
}
