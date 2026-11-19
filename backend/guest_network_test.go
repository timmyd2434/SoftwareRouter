package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func guestTestRuleset(t *testing.T, allow []GuestAllowRule) string {
	t.Helper()
	fm := &FirewallManager{}
	rs, err := fm.generateFullRulesetGuest(
		[]string{"eth0"}, []string{"br0"}, []string{"eth1.20"},
		allow, testCfg(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestIsGuestLabel(t *testing.T) {
	for _, l := range []string{"Guest", "guest", " IoT ", "iot", "Isolated"} {
		if !isGuestLabel(l) {
			t.Errorf("%q should be a guest label", l)
		}
	}
	for _, l := range []string{"", "LAN", "WAN", "DMZ", "Management", "Trunk"} {
		if isGuestLabel(l) {
			t.Errorf("%q must not be a guest label", l)
		}
	}
}

func TestGuestInterfaceIsIsolated(t *testing.T) {
	rs := guestTestRuleset(t, []GuestAllowRule{
		{Name: "Jellyfin via NPM", Destination: "192.168.3.102", Protocol: "tcp", Ports: []int{443}, Enabled: true},
	})

	mustContain := []string{
		`iifname "eth1.20" udp dport 67 accept`,
		`iifname "eth1.20" udp dport 53 accept`,
		`iifname "eth1.20" tcp dport 53 accept`,
		`iifname "eth1.20" oifname "eth0" accept comment "Guest to WAN"`,
		`iifname "eth1.20" ip daddr 192.168.3.102 tcp dport 443 accept`,
	}
	for _, want := range mustContain {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset is missing %q", want)
		}
	}

	for _, line := range strings.Split(rs, "\n") {
		// Guest must never be LAN-trusted, get SSH, or be forwarded to/from a LAN.
		if strings.Contains(line, `iifname "eth1.20" accept`) {
			t.Errorf("guest interface got blanket trust: %q", line)
		}
		if strings.Contains(line, `"eth1.20" tcp dport 22`) {
			t.Errorf("guest interface got SSH: %q", line)
		}
		if strings.Contains(line, `iifname "eth1.20" oifname "br0"`) || strings.Contains(line, `iifname "br0" oifname "eth1.20"`) {
			t.Errorf("guest <-> LAN forwarding present: %q", line)
		}
		if strings.Contains(line, `oifname "eth1.20"`) {
			t.Errorf("unexpected rule forwarding into the guest interface: %q", line)
		}
		// Guest must not be redirected to the router web UI either.
		if strings.Contains(line, `iifname "eth1.20"`) && strings.Contains(line, "dnat") {
			t.Errorf("guest interface got a DNAT rule: %q", line)
		}
	}
}

func TestGuestAutoDetectedInterfaceIsNotLAN(t *testing.T) {
	// The old generator treated every non-WAN interface as LAN. A plain
	// generateFullRuleset call (no guest list) must keep doing that, so the
	// guest-aware entry point is the only thing that changes behaviour.
	fm := &FirewallManager{}
	rs, err := fm.generateFullRuleset([]string{"eth0"}, []string{"br0", "eth1.20"}, testCfg(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rs, `iifname "eth1.20" accept comment "LAN trust"`) {
		t.Error("legacy entry point should still LAN-trust interfaces it is told are LAN")
	}
}

func TestGuestAllowRuleValidation(t *testing.T) {
	bad := []GuestAllowRule{
		{Name: "no dest", Destination: "", Ports: []int{443}, Enabled: true},
		{Name: "hostname", Destination: "jellyfin.example.com", Ports: []int{443}, Enabled: true},
		{Name: "injection", Destination: "1.2.3.4 accept", Ports: []int{443}, Enabled: true},
		{Name: "ipv6", Destination: "fd00::1", Ports: []int{443}, Enabled: true},
		{Name: "bad proto", Destination: "192.168.3.102", Protocol: "icmp", Ports: []int{443}, Enabled: true},
		{Name: "zero port", Destination: "192.168.3.102", Ports: []int{0}, Enabled: true},
		{Name: "big port", Destination: "192.168.3.102", Ports: []int{70000}, Enabled: true},
		{Name: "no ports", Destination: "192.168.3.102", Enabled: true},
	}
	rs := guestTestRuleset(t, bad)
	if strings.Contains(rs, "ip daddr") && strings.Contains(rs, `"eth1.20" ip daddr`) {
		t.Errorf("invalid guest_allow rules must be skipped, got:\n%s", rs)
	}
	// ...but a bad rule must not stop the firewall from being generated, or the
	// good rules around it.
	mixed := append(bad, GuestAllowRule{Name: "ok", Destination: "192.168.3.0/24", Protocol: "udp", Ports: []int{53, 123}, Enabled: true})
	rs = guestTestRuleset(t, mixed)
	if !strings.Contains(rs, `iifname "eth1.20" ip daddr 192.168.3.0/24 udp dport { 53, 123 } accept`) {
		t.Errorf("valid rule next to invalid ones was lost:\n%s", rs)
	}
}

func TestGuestRulesetRejectsInjectedInterface(t *testing.T) {
	fm := &FirewallManager{}
	_, err := fm.generateFullRulesetGuest([]string{"eth0"}, []string{"br0"},
		[]string{`eth1" accept comment "x`}, nil, testCfg(nil), nil)
	if err == nil {
		t.Error("injected guest interface name must be rejected")
	}
}

func TestGuestRulesetPassesNftCheck(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	rs := guestTestRuleset(t, []GuestAllowRule{
		{Name: "Jellyfin via NPM", Destination: "192.168.3.102", Ports: []int{80, 443}, Enabled: true},
		{Name: "NTP", Destination: "192.168.3.1", Protocol: "udp", Ports: []int{123}, Enabled: true},
	})
	f, _ := os.CreateTemp("", "guest-*.nft")
	f.WriteString(rs)
	f.Close()
	defer os.Remove(f.Name())
	if out, err := exec.Command("nft", "-c", "-f", f.Name()).CombinedOutput(); err != nil {
		t.Errorf("guest ruleset failed nft -c: %v\n%s\n---\n%s", err, out, rs)
	}
}

func TestDisabledGuestRuleIsNotEmitted(t *testing.T) {
	rs := guestTestRuleset(t, []GuestAllowRule{
		{Name: "off", Destination: "192.168.3.102", Ports: []int{443}, Enabled: false},
	})
	if strings.Contains(rs, "ip daddr 192.168.3.102") {
		t.Errorf("disabled rule must not appear in the ruleset:\n%s", rs)
	}
}

func TestNormalizeGuestAllowRule(t *testing.T) {
	got, err := normalizeGuestAllowRule(GuestAllowRule{
		Name: "  Jellyfin  ", Destination: " 192.168.3.102 ", Protocol: " TCP ", Ports: []int{443, 80, 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Jellyfin" || got.Destination != "192.168.3.102" || got.Protocol != "tcp" {
		t.Errorf("not normalised: %+v", got)
	}
	if len(got.Ports) != 2 || got.Ports[0] != 443 || got.Ports[1] != 80 {
		t.Errorf("ports should be de-duplicated in order, got %v", got.Ports)
	}
	if d, _ := normalizeGuestAllowRule(GuestAllowRule{Destination: "10.0.0.1", Ports: []int{1}}); d.Protocol != "tcp" {
		t.Error("protocol should default to tcp")
	}
	for _, bad := range []GuestAllowRule{
		{Name: `a"b`, Destination: "10.0.0.1", Ports: []int{1}},
		{Name: "a\\b", Destination: "10.0.0.1", Ports: []int{1}},
		{Name: "line\nbreak", Destination: "10.0.0.1", Ports: []int{1}},
		{Name: strings.Repeat("x", 65), Destination: "10.0.0.1", Ports: []int{1}},
	} {
		if _, err := normalizeGuestAllowRule(bad); err == nil {
			t.Errorf("expected %+v to be rejected", bad)
		}
	}
}

func TestGuestAllowStoreRoundTrip(t *testing.T) {
	oldPath, oldStore, oldReady := guestConfigPath, guestStore, guestStoreReady
	defer func() { guestConfigPath, guestStore, guestStoreReady = oldPath, oldStore, oldReady }()
	guestConfigPath = t.TempDir() + "/guest_access.json"
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false

	if n := len(GetGuestAllowRules()); n != 0 {
		t.Fatalf("missing file should mean no rules, got %d", n)
	}
	want := []GuestAllowRule{{ID: "1", Name: "Jellyfin", Destination: "192.168.3.102", Protocol: "tcp", Ports: []int{443}, Enabled: true}}
	if err := setGuestAllowRules(want); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(guestConfigPath); err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("store file should exist with mode 0600: %v %v", fi, err)
	}
	// Simulate a restart: forget memory, read from disk.
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false
	got := GetGuestAllowRules()
	if len(got) != 1 || got[0].ID != "1" || got[0].Destination != "192.168.3.102" || !got[0].Enabled {
		t.Errorf("rules did not survive a reload: %+v", got)
	}
	// A corrupt file must not wipe rules already in memory.
	os.WriteFile(guestConfigPath, []byte("{not json"), 0600)
	loadGuestAllowRules()
	if len(GetGuestAllowRules()) != 1 {
		t.Error("corrupt file wiped the in-memory rules")
	}
}

// The handlers must reject bad input before touching the store or the firewall.
func TestGuestAccessHandlersRejectBadInput(t *testing.T) {
	oldPath, oldStore, oldReady := guestConfigPath, guestStore, guestStoreReady
	defer func() { guestConfigPath, guestStore, guestStoreReady = oldPath, oldStore, oldReady }()
	guestConfigPath = t.TempDir() + "/guest_access.json"
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false

	call := func(h http.HandlerFunc, method, url, body string) int {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}
	cases := []struct {
		name   string
		h      http.HandlerFunc
		method string
		url    string
		body   string
		want   int
	}{
		{"create: not JSON", createGuestAccessRule, "POST", "/api/guest-access", "nope", 400},
		{"create: hostname destination", createGuestAccessRule, "POST", "/api/guest-access", `{"destination":"jellyfin.example.com","ports":[443]}`, 400},
		{"create: injection in destination", createGuestAccessRule, "POST", "/api/guest-access", `{"destination":"1.2.3.4 accept","ports":[443]}`, 400},
		{"create: port 0", createGuestAccessRule, "POST", "/api/guest-access", `{"destination":"192.168.3.102","ports":[0]}`, 400},
		{"create: no ports", createGuestAccessRule, "POST", "/api/guest-access", `{"destination":"192.168.3.102","ports":[]}`, 400},
		{"update: missing id", updateGuestAccessRule, "PUT", "/api/guest-access", `{"destination":"192.168.3.102","ports":[443]}`, 400},
		{"update: unknown id", updateGuestAccessRule, "PUT", "/api/guest-access?id=nope", `{"destination":"192.168.3.102","ports":[443]}`, 404},
		{"delete: missing id", deleteGuestAccessRule, "DELETE", "/api/guest-access", "", 400},
		{"delete: unknown id", deleteGuestAccessRule, "DELETE", "/api/guest-access?id=nope", "", 404},
	}
	for _, c := range cases {
		if got := call(c.h, c.method, c.url, c.body); got != c.want {
			t.Errorf("%s: got HTTP %d, want %d", c.name, got, c.want)
		}
	}
	if n := len(GetGuestAllowRules()); n != 0 {
		t.Errorf("rejected requests must not change the store, found %d rules", n)
	}
	if _, err := os.Stat(guestConfigPath); err == nil {
		t.Error("rejected requests must not write the store file")
	}
}

func TestStaleVLANLabels(t *testing.T) {
	exists := map[string]bool{"eno1.20": true, "eno1.30": true, "enp3s0f1": true}
	persisted := map[string]bool{"eno1.40": true} // defined but not up yet
	names := []string{
		"eno1.20", "eno1.30", // present: keep
		"eno1.3", "eno1.4", "enp3s0f0.30", // deleted VLANs: stale
		"eno1.40",  // persisted VLAN that is not up: keep
		"enp3s0f1", // physical NIC: keep
		"enp9s0f9", // missing physical NIC: never pruned (not VLAN-style)
		"br0",      // bridge: never pruned
	}
	got := staleVLANLabels(names,
		func(n string) bool { return exists[n] },
		func(n string) bool { return persisted[n] })
	want := []string{"eno1.3", "eno1.4", "enp3s0f0.30"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("stale labels = %v, want %v", got, want)
	}
}
