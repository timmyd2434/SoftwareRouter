package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testWGBase = "[Interface]\nPrivateKey = SERVERPRIV\nAddress = 10.8.0.1/24\nListenPort = 51820\nPostUp = nft add table inet wg-filter\n"

// The exact broken state from the field: two peers named "Phone" claiming 10.8.0.2.
const testWGDuplicates = testWGBase + `
[Peer]
# Name: Phone
PublicKey = EhzZl50X4Y2J/Avk0bRtIURIyVht1P2rTpfhPnqptA0=
AllowedIPs = 10.8.0.2/32

[Peer]
# Name: Phone
PublicKey = +C72SVzYah7xOeQnbxQL5GI63N0ff46rMZq7L0IOsVw=
AllowedIPs = 10.8.0.2/32
`

func TestParseAndAllocatePeers(t *testing.T) {
	peers := parseWGPeers(testWGDuplicates)
	if len(peers) != 2 || peers[0].Name != "Phone" || peers[1].PublicKey != "+C72SVzYah7xOeQnbxQL5GI63N0ff46rMZq7L0IOsVw=" {
		t.Fatalf("bad parse: %+v", peers)
	}
	addr, err := nextFreeWGAddress(peers)
	if err != nil || addr != "10.8.0.3/32" {
		t.Fatalf("expected 10.8.0.3/32 (2 is taken), got %q %v", addr, err)
	}
	// gaps are reused, the server address is never handed out
	gap := appendWGPeer(appendWGPeer(testWGBase, "a", "k1", "10.8.0.2/32"), "c", "k3", "10.8.0.4/32")
	if a, _ := nextFreeWGAddress(parseWGPeers(gap)); a != "10.8.0.3/32" {
		t.Errorf("gap not reused: %s", a)
	}
	if a, _ := nextFreeWGAddress(nil); a != "10.8.0.2/32" {
		t.Errorf("first client must be .2, got %s", a)
	}
}

func TestRemovePeersByNameRemovesEveryDuplicateAndKeepsInterface(t *testing.T) {
	out, keys := removeWGPeersByName(testWGDuplicates, "Phone")
	if len(keys) != 2 {
		t.Fatalf("expected both duplicate keys, got %v", keys)
	}
	if strings.Contains(out, "[Peer]") || !strings.Contains(out, "PrivateKey = SERVERPRIV") || !strings.Contains(out, "PostUp = nft add table") {
		t.Errorf("interface section must survive, peers must go:\n%s", out)
	}
	two := appendWGPeer(appendWGPeer(testWGBase, "keep", "kK", "10.8.0.2/32"), "drop", "kD", "10.8.0.3/32")
	out2, keys2 := removeWGPeersByName(two, "drop")
	if len(keys2) != 1 || keys2[0] != "kD" || !strings.Contains(out2, "# Name: keep") || strings.Contains(out2, "kD") {
		t.Errorf("selective removal failed:\n%s", out2)
	}
}

func TestClientConfigImportsWithoutEdits(t *testing.T) {
	c := buildWGClientConfig("PRIV", "10.8.0.5/32", "SERVERPUB=", "vpn.example.com")
	for _, want := range []string{"Address = 10.8.0.5/32", "Endpoint = vpn.example.com:51820", "AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25", "PublicKey = SERVERPUB="} {
		if !strings.Contains(c, want) {
			t.Errorf("client config missing %q", want)
		}
	}
	if got := formatWGEndpoint("2001:db8::1", 51820); got != "[2001:db8::1]:51820" {
		t.Errorf("IPv6 endpoint must be bracketed, got %s", got)
	}
}

func setupWGTest(t *testing.T) (confPath string) {
	t.Helper()
	dir := t.TempDir()
	oldConf, oldClients, oldPub := wgConfPath, wgClientsDir, wgServerPubKeyPath
	wgConfPath = filepath.Join(dir, "wg0.conf")
	wgClientsDir = filepath.Join(dir, "clients")
	wgServerPubKeyPath = filepath.Join(dir, "server.pub")
	t.Cleanup(func() { wgConfPath, wgClientsDir, wgServerPubKeyPath = oldConf, oldClients, oldPub })
	os.WriteFile(wgConfPath, []byte(testWGDuplicates), 0600)
	os.WriteFile(wgServerPubKeyPath, []byte("UgawZLtzkrRTNh220ormMNK/FrH8HrQC6OPyhmLywBo=\n"), 0600)

	oldResolver := resolveVPNEndpoint
	resolveVPNEndpoint = func() (string, error) { return "vpn.example.com", nil }
	t.Cleanup(func() { resolveVPNEndpoint = oldResolver })
	return wgConfPath
}

func TestAddAndDeleteVPNClientEndToEnd(t *testing.T) {
	if _, err := os.Stat("/usr/bin/wg"); err != nil {
		t.Skip("wireguard-tools not installed")
	}
	conf := setupWGTest(t)

	post := func(name string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"name": name})
		rr := httptest.NewRecorder()
		addVPNClient(rr, httptest.NewRequest("POST", "/api/vpn/clients", bytes.NewReader(body)))
		return rr
	}

	rr := post("Tablet")
	if rr.Code != http.StatusOK {
		t.Fatalf("add failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	cfg, _ := resp["config"].(string)
	// the config must be importable as-is: public endpoint, unique address, server key
	if !strings.Contains(cfg, "Endpoint = vpn.example.com:51820") || strings.Contains(cfg, "192.168.") || strings.Contains(cfg, "localhost") {
		t.Errorf("endpoint wrong:\n%s", cfg)
	}
	if !strings.Contains(cfg, "Address = 10.8.0.3/32") {
		t.Errorf("address must skip the taken .2:\n%s", cfg)
	}
	if !strings.Contains(cfg, "PublicKey = UgawZLtzkrRTNh220ormMNK/FrH8HrQC6OPyhmLywBo=") {
		t.Errorf("server key missing:\n%s", cfg)
	}
	saved, _ := os.ReadFile(conf)
	if !strings.Contains(string(saved), "# Name: Tablet") || len(parseWGPeers(string(saved))) != 3 {
		t.Errorf("peer not persisted:\n%s", saved)
	}
	if fi, _ := os.Stat(conf); fi.Mode().Perm() != 0600 {
		t.Errorf("wg0.conf must stay 0600, got %v", fi.Mode().Perm())
	}
	if post("Tablet").Code != http.StatusConflict {
		t.Error("duplicate name must be refused (409)")
	}
	if rr2 := post("Laptop"); rr2.Code != http.StatusOK || !strings.Contains(rr2.Body.String(), "10.8.0.4/32") {
		t.Errorf("second client must get .4: %d %s", rr2.Code, rr2.Body.String())
	}

	// delete removes the peer block AND the client file
	rr3 := httptest.NewRecorder()
	deleteVPNClient(rr3, httptest.NewRequest("DELETE", "/api/vpn/clients?name=Tablet", nil))
	after, _ := os.ReadFile(conf)
	if strings.Contains(string(after), "# Name: Tablet") {
		t.Errorf("peer block must be removed on delete:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(wgClientsDir, "Tablet.conf")); err == nil {
		t.Error("client file must be removed")
	}
	// ...so the freed address is reusable without ever duplicating a live one
	if rr4 := post("Tablet"); !strings.Contains(rr4.Body.String(), "10.8.0.3/32") {
		t.Errorf("freed address should be reused: %s", rr4.Body.String())
	}
}

func TestAddClientRefusesWhenEndpointUnknown(t *testing.T) {
	setupWGTest(t)
	resolveVPNEndpoint = func() (string, error) { return "", fmt.Errorf("hostname configured but empty") }
	body, _ := json.Marshal(map[string]string{"name": "x"})
	rr := httptest.NewRecorder()
	addVPNClient(rr, httptest.NewRequest("POST", "/api/vpn/clients", bytes.NewReader(body)))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("must refuse to emit a config that cannot work, got %d", rr.Code)
	}
	if b, _ := os.ReadFile(wgConfPath); strings.Contains(string(b), "# Name: x") {
		t.Error("no peer may be created when the endpoint is unknown")
	}
}

func TestFirewallTrustsWireGuardPeers(t *testing.T) {
	setupWGTest(t) // wg0.conf exists -> WireGuard is "enabled"
	fm := &FirewallManager{}
	rs, err := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`iifname "wg0" accept comment "WireGuard peers (trusted)"`, `iifname "wg0" accept comment "WireGuard peers to LAN/WAN"`, `iifname "eth0" udp dport 51820 accept`} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q", want)
		}
	}
	// and without a WireGuard server there are no wg0 rules at all
	os.Remove(wgConfPath)
	rs2, _ := fm.generateFullRuleset([]string{"eth0"}, []string{"br0"}, testCfg(nil), nil)
	if strings.Contains(rs2, "wg0") || strings.Contains(rs2, "51820") {
		t.Error("no WireGuard rules expected when wg0.conf is absent")
	}
}
