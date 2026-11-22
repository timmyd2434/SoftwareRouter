package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBondOptionValuesAreChecked(t *testing.T) {
	good := map[string][]string{
		"miimon":           {"0", "100", "10000"},
		"lacp_rate":        {"slow", "fast"},
		"xmit_hash_policy": {"layer2", "layer2+3", "layer3+4"},
	}
	for opt, vals := range good {
		for _, v := range vals {
			if !bondOptions[opt](v) {
				t.Errorf("%s=%s should be accepted", opt, v)
			}
		}
	}
	bad := map[string][]string{
		"miimon":           {"", "-1", "10001", "abc", "0100", "1 2", "100;id"},
		"lacp_rate":        {"", "medium", "slow; id"},
		"xmit_hash_policy": {"", "layer5", "layer3+4 foo"},
	}
	for opt, vals := range bad {
		for _, v := range vals {
			if bondOptions[opt](v) {
				t.Errorf("%s=%q must be rejected", opt, v)
			}
		}
	}
}

func TestSetBondOptionRejectsBadInputBeforeRunningAnything(t *testing.T) {
	for _, c := range []struct{ bond, opt, val string }{
		{"bond0 x", "miimon", "100"},
		{"bond0", "mode", "1"}, // changing the mode is not allowed here
		{"bond0", "arp_ip_target", "1.2.3.4"},
		{"bond0", "miimon", "abc"},
		{"bond0", "lacp_rate", "slow; id"},
	} {
		if err := setBondOption(c.bond, c.opt, c.val); err == nil {
			t.Errorf("setBondOption(%q,%q,%q) should be rejected", c.bond, c.opt, c.val)
		}
	}
}

func TestExecutorPolicyAllowsTheBondCommands(t *testing.T) {
	for _, args := range [][]string{
		{"link", "set", "dev", "bond0", "type", "bond", "miimon", "100"},
		{"link", "set", "dev", "bond0", "type", "bond", "lacp_rate", "slow"},
		{"link", "set", "dev", "bond0", "type", "bond", "xmit_hash_policy", "layer3+4"},
	} {
		if err := validateCommand("ip", args); err != nil {
			t.Errorf("policy rejects %v: %v", args, err)
		}
	}
}

// The backend must not write bonding parameters to sysfs itself any more. (Reading them, to show
// the current status, is fine: those files are world-readable.)
func TestNoDirectBondingSysfsWrites(t *testing.T) {
	assign := regexp.MustCompile(`(\w+)\s*:=\s*filepath\.Join\("/sys/class/net".*"bonding", "(?:miimon|lacp_rate|xmit_hash_policy)"\)`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		for _, m := range assign.FindAllStringSubmatch(string(src), -1) {
			if strings.Contains(string(src), "os.WriteFile("+m[1]+",") {
				t.Errorf("%s writes the bonding parameter %s through sysfs; use setBondOption", f, m[1])
			}
		}
	}
}
