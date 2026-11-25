package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func dnsRuleset(t *testing.T, s GuestSettings) string {
	t.Helper()
	fm := &FirewallManager{}
	rs, err := fm.generateFullRulesetGuest([]string{"eth0"}, []string{"br0"}, []string{"eth1.20", "eth1.30"},
		[]GuestAllowRule{{Name: "Jellyfin", Destination: "192.168.3.102", Ports: []int{443}, Enabled: true}},
		testCfg(func(c *Config) { c.GuestSettings = s }), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestGuestDNSRulesAreOffByDefault(t *testing.T) {
	rs := dnsRuleset(t, GuestSettings{})
	for _, bad := range []string{"redirect to :53", "dport 53 counter drop", "dport 853", "Guest DoH block", "Guest DNS enforcement"} {
		if strings.Contains(rs, bad) {
			t.Errorf("default settings must not add %q", bad)
		}
	}
}

func TestEnforceDNSRedirectsAndDropsOnlyForGuests(t *testing.T) {
	rs := dnsRuleset(t, GuestSettings{EnforceDNS: true})
	for _, g := range []string{"eth1.20", "eth1.30"} {
		for _, want := range []string{
			`iifname "` + g + `" udp dport 53 fib daddr type != local counter redirect to :53`,
			`iifname "` + g + `" tcp dport 53 fib daddr type != local counter redirect to :53`,
			`iifname "` + g + `" meta l4proto { tcp, udp } th dport 53 counter drop`,
		} {
			if !strings.Contains(rs, want) {
				t.Errorf("missing %q", want)
			}
		}
	}
	for _, line := range strings.Split(rs, "\n") {
		if (strings.Contains(line, "redirect to :53") || strings.Contains(line, "th dport 53 counter drop")) &&
			!strings.Contains(line, `iifname "eth1.`) {
			t.Errorf("DNS enforcement must be limited to guest interfaces: %s", line)
		}
	}
	// The drops must come before the guest accept rules, or they would never be reached.
	drop := strings.Index(rs, `iifname "eth1.20" meta l4proto { tcp, udp } th dport 53 counter drop`)
	accept := strings.Index(rs, `iifname "eth1.20" oifname "eth0" accept comment "Guest to WAN"`)
	allow := strings.Index(rs, `iifname "eth1.20" ip daddr 192.168.3.102 tcp dport 443 accept`)
	if drop < 0 || accept < 0 || allow < 0 || drop > accept || drop > allow {
		t.Errorf("drops must precede the guest accepts (drop=%d allow=%d accept=%d)", drop, allow, accept)
	}
	if strings.Contains(rs, "dport 853") || strings.Contains(rs, "Guest DoH block") {
		t.Error("only DNS enforcement was enabled")
	}
}

func TestBlockDoTAndDoHAreIndependentSettings(t *testing.T) {
	dot := dnsRuleset(t, GuestSettings{BlockDoT: true})
	if !strings.Contains(dot, `iifname "eth1.20" meta l4proto { tcp, udp } th dport 853 counter drop`) {
		t.Error("DoT/DoQ block missing")
	}
	if strings.Contains(dot, "redirect to :53") || strings.Contains(dot, "Guest DoH block") {
		t.Error("only the DoT block was enabled")
	}
	doh := dnsRuleset(t, GuestSettings{BlockDoH: true})
	for _, want := range []string{
		`iifname "eth1.20" ip daddr {`, `ip6 daddr {`, "1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111", " tcp dport 443 counter drop", " udp dport 443 counter drop",
	} {
		if !strings.Contains(doh, want) {
			t.Errorf("DoH block missing %q", want)
		}
	}
	if strings.Contains(doh, "th dport 853") {
		t.Error("only the DoH block was enabled")
	}
}

func TestResolverListsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range dohResolversV4 {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() == nil {
			t.Errorf("%q is not an IPv4 address", a)
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
			t.Errorf("%s must not be a private or special address", a)
		}
		if seen[a] {
			t.Errorf("duplicate %s", a)
		}
		seen[a] = true
	}
	for _, a := range dohResolversV6 {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() != nil {
			t.Errorf("%q is not an IPv6 address", a)
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Errorf("%s must not be a private or special address", a)
		}
		if seen[a] {
			t.Errorf("duplicate %s", a)
		}
		seen[a] = true
	}
	// A router must never block its own users' LAN resolvers by accident.
	for _, a := range dohResolversV4 {
		if strings.HasPrefix(a, "192.168.") || strings.HasPrefix(a, "10.") {
			t.Errorf("%s is a LAN address", a)
		}
	}
}

func TestFullRulesetWithEverythingOnIsValidAndAcceptedByTheHelper(t *testing.T) {
	rs := dnsRuleset(t, GuestSettings{EnforceDNS: true, BlockDoT: true, BlockDoH: true})
	if err := validateNftablesConf(rs); err != nil {
		t.Errorf("the helper would refuse this ruleset: %v", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	f, _ := os.CreateTemp("", "dns-*.nft")
	f.WriteString(rs)
	f.Close()
	defer os.Remove(f.Name())
	if out, err := exec.Command("nft", "-c", "-f", f.Name()).CombinedOutput(); err != nil {
		t.Errorf("nft -c rejected the ruleset: %v\n%s", err, out)
	}
	if dups := duplicateRulesIn(rs); len(dups) != 0 {
		t.Errorf("duplicate rules: %v", dups)
	}
}

func TestGuestStorePersistsSettingsAndRulesTogether(t *testing.T) {
	oldPath, oldStore, oldReady := guestConfigPath, guestStore, guestStoreReady
	defer func() { guestConfigPath, guestStore, guestStoreReady = oldPath, oldStore, oldReady }()
	guestConfigPath = t.TempDir() + "/guest_access.json"
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false

	if GetGuestSettings() != (GuestSettings{}) {
		t.Fatal("settings must default to all off")
	}
	rule := GuestAllowRule{ID: "1", Destination: "10.0.0.1", Ports: []int{1}, Enabled: true}
	if err := setGuestAllowRules([]GuestAllowRule{rule}); err != nil {
		t.Fatal(err)
	}
	want := GuestSettings{EnforceDNS: true, BlockDoT: true}
	if err := setGuestSettings(want); err != nil {
		t.Fatal(err)
	}
	// Saving rules must not reset the settings, and saving settings must not drop the rules.
	if err := setGuestAllowRules([]GuestAllowRule{rule, {ID: "2", Destination: "10.0.0.2", Ports: []int{2}, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false // simulate a restart
	if got := GetGuestSettings(); got != want {
		t.Errorf("settings after restart = %+v, want %+v", got, want)
	}
	if n := len(GetGuestAllowRules()); n != 2 {
		t.Errorf("rules after restart = %d, want 2", n)
	}
}

func TestLegacyStoreFileWithoutSettingsStillLoads(t *testing.T) {
	oldPath, oldStore, oldReady := guestConfigPath, guestStore, guestStoreReady
	defer func() { guestConfigPath, guestStore, guestStoreReady = oldPath, oldStore, oldReady }()
	guestConfigPath = t.TempDir() + "/guest_access.json"
	os.WriteFile(guestConfigPath, []byte(`{"rules":[{"id":"a","destination":"10.0.0.1","protocol":"tcp","ports":[443],"enabled":true}]}`), 0600)
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false
	if n := len(GetGuestAllowRules()); n != 1 {
		t.Errorf("legacy rules = %d, want 1", n)
	}
	if GetGuestSettings() != (GuestSettings{}) {
		t.Error("a legacy file must give all-off settings")
	}
}

func TestSettingsHandlerRejectsBadInput(t *testing.T) {
	oldPath, oldStore, oldReady := guestConfigPath, guestStore, guestStoreReady
	defer func() { guestConfigPath, guestStore, guestStoreReady = oldPath, oldStore, oldReady }()
	guestConfigPath = t.TempDir() + "/guest_access.json"
	guestStore, guestStoreReady = guestAllowStore{Rules: []GuestAllowRule{}}, false

	for _, body := range []string{"nope", `{"enforce_dns":"yes"}`, `{"enforce_dns":true,"extra":1}`, ""} {
		rec := httptest.NewRecorder()
		updateGuestSettings(rec, httptest.NewRequest(http.MethodPut, "/api/guest-access/settings", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: got HTTP %d, want 400", body, rec.Code)
		}
	}
	if GetGuestSettings() != (GuestSettings{}) {
		t.Error("rejected requests must not change the settings")
	}
	if _, err := os.Stat(guestConfigPath); err == nil {
		t.Error("rejected requests must not write the store file")
	}
}
