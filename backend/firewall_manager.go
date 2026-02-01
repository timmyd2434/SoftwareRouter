package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// FirewallManager handles the generation and application of NFTables rules
type FirewallManager struct {
	mu sync.Mutex
}

var firewallManager = &FirewallManager{}

// InitFirewallManager initializes the manager
func InitFirewallManager() {
	// Ensure tables exist
	exec.Command("nft", "add", "table", "inet", "softrouter").Run()
	exec.Command("nft", "add", "table", "ip", "nat").Run()

	// Enable route_localnet to allow DNAT to 127.0.0.1
	// This is critical for the new security model where we bind to localhost but dnat from LAN
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.default.route_localnet=1").Run()
}

// ApplyFirewallRules regenerates and applies all firewall rules
func (fm *FirewallManager) ApplyFirewallRules() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fmt.Println("Regenerating NFTables Ruleset...")

	// 1. Load Context (Interfaces, Config, Rules)
	metaStore, err := loadInterfaceMetadata()
	if err != nil {
		fmt.Printf("Warning: Failed to load interface metadata: %v\n", err)
		metaStore = &InterfaceMetadataStore{Metadata: make(map[string]InterfaceMetadata)}
	}

	configLock.RLock()
	cfg := config
	configLock.RUnlock()

	pfRules := GetPortForwardingRules() // Need to implement this in nat_utils.go

	// 2. Determine Interface Groups
	wanInterfaces := []string{}
	lanInterfaces := []string{}

	// Auto-detect if no explicit labels
	hasExplicitWan := false
	for _, m := range metaStore.Metadata {
		if strings.EqualFold(m.Label, "WAN") {
			hasExplicitWan = true
			break
		}
	}

	for iface, meta := range metaStore.Metadata {
		if strings.EqualFold(meta.Label, "WAN") {
			wanInterfaces = append(wanInterfaces, iface)
		} else if strings.EqualFold(meta.Label, "LAN") {
			lanInterfaces = append(lanInterfaces, iface)
		}
	}

	// Fallback detection if no WAN explicitly labeled
	if !hasExplicitWan {
		defWan, err := getDefaultGatewayInterface()
		if err == nil && defWan != "" {
			fmt.Printf("Auto-detected WAN interface: %s\n", defWan)
			wanInterfaces = append(wanInterfaces, defWan)
			// Implicitly treat others as LAN? Or just rely on explicit WAN dropping.
		}
	}

	// If we have WAN interfaces, we can define the sets.
	// If not, we fall back to a "Permissive" mode or "Dev" mode.
	// For safety, if no WAN is defined, we might not block much, OR we block everything external.
	// Let's assume standard router behavior: Block Input/Forward on WAN.

	// 3. Generate Ruleset Script
	// We will build a batch script for `nft -f` to apply atomically (best practice),
	// but for now we might sequentially run commands or build a large string.
	// Sequential commands are easier to debug in this agent context.

	// --- FLUSH CHAINS ---
	exec.Command("nft", "flush", "chain", "inet", "softrouter", "input").Run()
	exec.Command("nft", "flush", "chain", "inet", "softrouter", "forward").Run()
	exec.Command("nft", "flush", "chain", "ip", "nat", "prerouting").Run()
	exec.Command("nft", "flush", "chain", "ip", "nat", "postrouting").Run()

	// Ensure Base Chains exist (hooks)
	exec.Command("nft", "add", "chain", "inet", "softrouter", "input", "{ type filter hook input priority 0; policy accept; }").Run()
	exec.Command("nft", "add", "chain", "inet", "softrouter", "forward", "{ type filter hook forward priority 0; policy accept; }").Run()
	exec.Command("nft", "add", "chain", "ip", "nat", "prerouting", "{ type nat hook prerouting priority -100; policy accept; }").Run()
	exec.Command("nft", "add", "chain", "ip", "nat", "postrouting", "{ type nat hook postrouting priority 100; policy accept; }").Run()

	// --- INET FILTER TABLE ---

	// INPUT Chain
	// 1. Accept Loopback
	exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "iif", "lo", "accept").Run()

	// 2. Accept Established/Related
	exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "ct", "state", "established,related", "accept").Run()

	// 3. Drop Invalid
	exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "ct", "state", "invalid", "drop").Run()

	// 4. Accept ICMP (Generic)
	exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "ip", "protocol", "icmp", "accept").Run()

	// 5. WAN/LAN Logic
	// If Access Control allows WAN, we rely on Prerouting DNAT to redirect ports to localhost/LAN IP.
	// So Input chain sees the transformed destination if DNAT happened?
	// Actually, for local input (router webui), if DNAT modifies daddr to 127.0.0.1, input sees 127.0.0.1?
	// RFC: If packet comes from WAN destined to WAN_IP:980, DNAT -> 127.0.0.1:80.
	// Input hook: iif WAN, daddr 127.0.0.1.
	// We need to allow this flow.
	// "ct state new" for these DNAT'd connections might need explicit accept.

	// Allow SSH (Port 22) - Configurable? Default YES for now to avoid lockout.
	exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "tcp", "dport", "22", "accept").Run()

	// Allow DHCP/DNS from LAN
	// We'll iterate LAN interfaces or just allow all RFC1918?
	// Safer to trust LAN interfaces.
	for _, iface := range lanInterfaces {
		exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "iifname", iface, "accept").Run()
	}

	// Drop logic for WAN
	for _, iface := range wanInterfaces {
		// Drop new connections from WAN that weren't DNAT'd?
		// Actually NFTables Input hook comes AFTER Prerouting.
		// If DNAT occurred, valid.
		// If we want to allow WAN Access to WebUI via DNAT, we likely need to accept packets that match the DNAT.
		// Explicitly:
		// nft add rule inet softrouter input iifname wan0 ct status dnat accept
		exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "iifname", iface, "ct", "status", "dnat", "accept").Run()

		// Drop everything else from WAN
		exec.Command("nft", "add", "rule", "inet", "softrouter", "input", "iifname", iface, "drop").Run()
	}

	// FORWARD Chain
	// 1. Accept Established/Related
	exec.Command("nft", "add", "rule", "inet", "softrouter", "forward", "ct", "state", "established,related", "accept").Run()

	// 2. Allow LAN -> WAN
	// iifname LAN oifname WAN accept
	for _, lan := range lanInterfaces {
		for _, wan := range wanInterfaces {
			exec.Command("nft", "add", "rule", "inet", "softrouter", "forward", "iifname", lan, "oifname", wan, "accept").Run()
		}
	}

	// 3. Allow Port Forwarding (WAN -> LAN via DNAT)
	// "ct status dnat accept"
	exec.Command("nft", "add", "rule", "inet", "softrouter", "forward", "ct", "status", "dnat", "accept").Run()

	// --- IP NAT TABLE ---

	// PREROUTING Chain

	// 1. Port Forwarding Rules
	for _, rule := range pfRules {
		if !rule.Enabled {
			continue
		}

		proto := rule.Protocol
		if proto == "" {
			proto = "tcp"
		}

		// dnat to InternalIP:InternalPort
		// Optionally restricted to iifname WAN? For now apply generally or restrict if WANs connect.
		dnatTarget := fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort)

		for _, wan := range wanInterfaces {
			exec.Command("nft", "add", "rule", "ip", "nat", "prerouting", "iifname", wan, proto, "dport", fmt.Sprintf("%d", rule.ExternalPort), "dnat", "to", dnatTarget).Run()
		}

		// Hairpin NAT Prerouting: Allow LAN hitting WAN_IP to DNAT too
		// We'll add this broadly for daddr <WAN_IP> if we knew it, or just generic dport on interface address.
		// For simplicity, we loop WAN interfaces, get their IP?
		// Let's skip complex Hairpin optimization for this iteration and focus on WAN Access.
	}

	// 2. LAN Access to WebUI (Since we listen on 127.0.0.1:8080 / :443)
	// We need to DNAT LAN traffic to localhost.
	// HTTP (LAN:80 -> Local:8080)
	for _, lan := range lanInterfaces {
		exec.Command("nft", "add", "rule", "ip", "nat", "prerouting", "iifname", lan, "tcp", "dport", "80", "dnat", "to", "127.0.0.1:8080").Run()
	}
	// HTTPS (LAN:443 -> Local:443 (or whatever TLS port is))
	// If config.TLS == :443, we bind 127.0.0.1:443.
	targetHTTPS := "443"
	if cfg.TLS.Port != "" {
		targetHTTPS = strings.TrimPrefix(cfg.TLS.Port, ":")
	}
	for _, lan := range lanInterfaces {
		exec.Command("nft", "add", "rule", "ip", "nat", "prerouting", "iifname", lan, "tcp", "dport", targetHTTPS, "dnat", "to", fmt.Sprintf("127.0.0.1:%s", targetHTTPS)).Run()
	}

	// 3. WAN Access to WebUI
	if cfg.WebAccess.AllowWAN {
		// Default ports if 0
		httpPort := cfg.WebAccess.WANPortHTTP
		if httpPort == 0 {
			httpPort = 980
		}

		httpsPort := cfg.WebAccess.WANPortHTTPS
		if httpsPort == 0 {
			httpsPort = 9443
		}

		// DNAT rule: tcp dport 980 dnat to 127.0.0.1:80
		// We should bind WebUI to 80 locally.

		for _, wan := range wanInterfaces {
			// HTTP (WAN:Port -> Local:8080)
			exec.Command("nft", "add", "rule", "ip", "nat", "prerouting", "iifname", wan, "tcp", "dport", fmt.Sprintf("%d", httpPort), "dnat", "to", "127.0.0.1:8080").Run()
			// HTTPS - assuming backend serves TLS on 443 locally or we map to config.TLS.Port
			// If config.TLS.Port is :443, we map to 443.
			targetHTTPS := "443"
			if cfg.TLS.Port != "" {
				targetHTTPS = strings.TrimPrefix(cfg.TLS.Port, ":")
			}
			exec.Command("nft", "add", "rule", "ip", "nat", "prerouting", "iifname", wan, "tcp", "dport", fmt.Sprintf("%d", httpsPort), "dnat", "to", fmt.Sprintf("127.0.0.1:%s", targetHTTPS)).Run()
		}
	}

	// POSTROUTING Chain

	// 1. Masquerade LAN -> WAN
	for _, wan := range wanInterfaces {
		exec.Command("nft", "add", "rule", "ip", "nat", "postrouting", "oifname", wan, "masquerade").Run()
	}

	// 2. Hairpin NAT Masquerade
	// If src is LAN and dest is LAN, masquerade.
	if cfg.ProtectedSubnet != "" {
		exec.Command("nft", "add", "rule", "ip", "nat", "postrouting", "ip", "saddr", cfg.ProtectedSubnet, "ip", "daddr", cfg.ProtectedSubnet, "masquerade").Run()
	}

	return nil
}
