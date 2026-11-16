package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// WireGuard server management.
//
// Goals: a client config downloaded from the WebUI imports into the phone
// as-is (no hand edits), and the server side needs no hand edits either.
//
//   - Endpoint comes from the configured VPN endpoint (static IP, DDNS name or
//     auto-detected public IP), never from the browser's Host header (which is
//     a LAN address when the UI is opened at home).
//   - Peer addresses are allocated from the peers actually present in wg0.conf,
//     so deleting and re-adding clients can never produce duplicates.
//   - Deleting a client also removes its [Peer] block and its live peer.
//   - New peers are loaded into the running interface with `wg set`
//     (`wg syncconf` rejects wg-quick style files), and persisted for restarts.

const (
	wgIface      = "wg0"
	wgListenPort = 51820
	wgServerIP   = "10.8.0.1"
	wgSubnet     = "10.8.0."
)

var (
	// Variables (not constants) so tests can point them at a temp directory.
	wgConfPath         = "/etc/wireguard/wg0.conf"
	wgClientsDir       = "/etc/softrouter/vpn_clients"
	wgServerPubKeyPath = "/etc/softrouter/vpn_server_public.key"
	wgMu               sync.Mutex
	wgKeyRe            = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	wgPeerAddrRe       = regexp.MustCompile(`^10\.8\.0\.([0-9]{1,3})/32$`)
)

// resolveVPNEndpoint is a hook so tests can supply an endpoint without touching
// the on-disk config or the network.
var resolveVPNEndpoint = getVPNEndpoint

type wgPeer struct {
	Name       string
	PublicKey  string
	AllowedIPs []string
	start, end int // line range [start, end) of the [Peer] block
}

// parseWGPeers returns the [Peer] blocks of a wg-quick config.
func parseWGPeers(content string) []wgPeer {
	lines := strings.Split(content, "\n")
	var peers []wgPeer
	cur := -1
	closeBlock := func(end int) {
		if cur >= 0 {
			peers[cur].end = end
		}
	}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			closeBlock(i)
			cur = -1
			if strings.EqualFold(line, "[Peer]") {
				peers = append(peers, wgPeer{start: i})
				cur = len(peers) - 1
			}
			continue
		}
		if cur < 0 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "# Name:"):
			peers[cur].Name = strings.TrimSpace(strings.TrimPrefix(line, "# Name:"))
		case strings.HasPrefix(line, "PublicKey"):
			if _, v, ok := strings.Cut(line, "="); ok {
				peers[cur].PublicKey = strings.TrimSpace(v)
			}
		case strings.HasPrefix(line, "AllowedIPs"):
			if _, v, ok := strings.Cut(line, "="); ok {
				for _, a := range strings.Split(v, ",") {
					if a = strings.TrimSpace(a); a != "" {
						peers[cur].AllowedIPs = append(peers[cur].AllowedIPs, a)
					}
				}
			}
		}
	}
	closeBlock(len(lines))
	return peers
}

// nextFreeWGAddress returns the lowest unused 10.8.0.N/32 (N = 2..254).
func nextFreeWGAddress(peers []wgPeer) (string, error) {
	used := map[int]bool{1: true}
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			if m := wgPeerAddrRe.FindStringSubmatch(a); m != nil {
				n, _ := strconv.Atoi(m[1])
				used[n] = true
			}
		}
	}
	for n := 2; n <= 254; n++ {
		if !used[n] {
			return fmt.Sprintf("%s%d/32", wgSubnet, n), nil
		}
	}
	return "", fmt.Errorf("VPN address pool exhausted (no free address in %s0/24)", wgSubnet)
}

func appendWGPeer(content, name, pubKey, addr string) string {
	content = strings.TrimRight(content, "\n")
	return content + fmt.Sprintf("\n\n[Peer]\n# Name: %s\nPublicKey = %s\nAllowedIPs = %s\n", name, pubKey, addr)
}

// removeWGPeersByName drops every [Peer] block with the given name and returns
// the new content plus the public keys that were removed.
func removeWGPeersByName(content, name string) (string, []string) {
	peers := parseWGPeers(content)
	lines := strings.Split(content, "\n")
	drop := make([]bool, len(lines))
	var keys []string
	for _, p := range peers {
		if p.Name != name {
			continue
		}
		keys = append(keys, p.PublicKey)
		for i := p.start; i < p.end && i < len(lines); i++ {
			drop[i] = true
		}
	}
	var out []string
	for i, l := range lines {
		if !drop[i] {
			out = append(out, l)
		}
	}
	res := strings.Join(out, "\n")
	// collapse the blank lines the removal leaves behind
	for strings.Contains(res, "\n\n\n") {
		res = strings.ReplaceAll(res, "\n\n\n", "\n\n")
	}
	return strings.TrimRight(res, "\n") + "\n", keys
}

// writeFileAtomic writes via a temp file in the same directory and renames, so
// a crash can never leave a half-written wg0.conf.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-wg-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// formatWGEndpoint renders host:port, bracketing IPv6 literals.
func formatWGEndpoint(host string, port int) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func buildWGClientConfig(clientPriv, addr, serverPub, endpointHost string) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
		clientPriv, addr, serverPub, formatWGEndpoint(endpointHost, wgListenPort))
}
