package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDHCPValidationBlocksInjection(t *testing.T) {
	bad := []DHCPConfig{
		{Enabled: true, StartIP: "192.168.1.10", EndIP: "192.168.1.20", Gateway: "192.168.1.1\ndhcp-script=/tmp/x"},
		{Enabled: true, StartIP: "192.168.1.10\nconf-file=/etc/shadow", EndIP: "192.168.1.20"},
		{Enabled: true, StartIP: "192.168.1.10", EndIP: "192.168.1.20", LeaseTime: "12h\nx"},
		{Enabled: true, StartIP: "192.168.1.10", EndIP: "192.168.1.20", DNSServers: []string{"1.1.1.1,evil"}},
		{Enabled: true, StartIP: "192.168.1.10"}, // missing end
	}
	for i, c := range bad {
		if validateDHCPConfigFields("br0", c) == nil {
			t.Errorf("case %d should be rejected", i)
		}
	}
	good := DHCPConfig{Enabled: true, StartIP: "192.168.1.10", EndIP: "192.168.1.20", Gateway: "192.168.1.1", LeaseTime: "12h", DNSServers: []string{"1.1.1.1"}}
	if err := validateDHCPConfigFields("br0", good); err != nil {
		t.Errorf("good config rejected: %v", err)
	}
	if err := regenerateDnsmasqDHCPConfig(&DHCPConfigStore{Configs: map[string]DHCPConfig{"br0": bad[0]}}); err == nil {
		t.Error("generator must refuse injected gateway")
	}
}

func TestStaticLeaseAndRAValidation(t *testing.T) {
	if validateStaticLease(StaticLease{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.5", Hostname: "pc-1"}) != nil {
		t.Error("valid lease rejected")
	}
	if validateStaticLease(StaticLease{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.5", Hostname: "pc\nx"}) == nil {
		t.Error("newline hostname accepted")
	}
	if validateRAConfig("br0", "2001:db8::/64", []string{"2001:4860:4860::8888"}) != nil {
		t.Error("valid RA rejected")
	}
	for _, p := range []string{"2001:db8::/48", "10.0.0.0/24", "2001:db8::/64; };\nfoo", "garbage"} {
		if validateRAConfig("br0", p, nil) == nil {
			t.Errorf("prefix %q should be rejected", p)
		}
	}
	if validateRAConfig("br0", "2001:db8::/64", []string{"1.1.1.1"}) == nil {
		t.Error("IPv4 RDNSS accepted")
	}
}

func TestSessionIdleAndAbsoluteTimeouts(t *testing.T) {
	ss := &SessionStore{sessions: map[string]*Session{}}
	ss.AddSession("tok", "admin", "1.2.3.4", "ua")
	sessionStoreBackup := sessionStore
	sessionStore = ss
	defer func() { sessionStore = sessionStoreBackup }()

	if !ss.ValidateSession("tok") {
		t.Fatal("fresh session must validate")
	}
	// Activity must NOT extend the absolute expiry
	exp := ss.sessions["tok"].ExpiresAt
	ss.UpdateLastUsed("tok")
	if !ss.sessions["tok"].ExpiresAt.Equal(exp) {
		t.Error("absolute expiry must not slide")
	}
	// Idle timeout
	ss.sessions["tok"].LastUsed = time.Now().Add(-idleTimeout - time.Minute)
	if ss.ValidateSession("tok") {
		t.Error("idle session must be rejected")
	}
	// Absolute timeout
	ss.AddSession("tok2", "admin", "1.2.3.4", "ua")
	ss.sessions["tok2"].ExpiresAt = time.Now().Add(-time.Second)
	if ss.ValidateSession("tok2") {
		t.Error("expired session must be rejected")
	}
	// Revocation
	ss.AddSession("a", "bob", "ip", "ua")
	ss.AddSession("b", "bob", "ip", "ua")
	if n := ss.RevokeAllUserSessions("bob"); n != 2 {
		t.Errorf("expected 2 revoked, got %d", n)
	}
}

func TestAuditUsernameComesFromSessionNotToken(t *testing.T) {
	sessionStore.AddSession("sr-evil-1-abc", "realuser", "ip", "ua")
	defer sessionStore.DeleteSession("sr-evil-1-abc")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer sr-evil-1-abc")
	if got := getUsernameFromToken(r); got != "realuser" {
		t.Errorf("got %q", got)
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("Authorization", "Bearer sr-forged-1-sig")
	if got := getUsernameFromToken(r2); got != "unknown" {
		t.Errorf("forged token must not yield a username, got %q", got)
	}
}

func TestControlPlaneNoUnscopedAccepts(t *testing.T) {
	locked := generateControlPlaneRules(Config{}, []string{"eth0"})
	if locked != "" {
		t.Error("no control plane rules expected after lockdown")
	}
	prov := generateControlPlaneRules(Config{ProvisioningMode: true}, []string{"eth0"})
	for _, l := range strings.Split(prov, "\n") {
		if strings.Contains(l, "dport") && !strings.Contains(l, "iifname") {
			t.Errorf("unscoped rule: %q", l)
		}
	}
}

func TestHostHeaderAllowlist(t *testing.T) {
	configLock.Lock()
	old := config.AllowedHosts
	config.AllowedHosts = []string{"router.home.arpa"}
	configLock.Unlock()
	defer func() { configLock.Lock(); config.AllowedHosts = old; configLock.Unlock() }()
	cases := map[string]bool{
		"router.home.arpa:443": true, "192.168.1.1": true, "localhost:8080": true,
		"evil.example.com": false, "attacker.rebind.net:443": false,
	}
	for h, want := range cases {
		if hostHeaderAllowed(h) != want {
			t.Errorf("%s: want %v", h, want)
		}
	}
}
