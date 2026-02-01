package main

import (
	"fmt"
	"os"
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

// ApplyFirewallRules regenerates and applies all firewall rules ATOMICALLY
func (fm *FirewallManager) ApplyFirewallRules() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fmt.Println("Regenerating NFTables Ruleset (Atomic Mode)...")

	// 1. Load Context
	metaStore, err := loadInterfaceMetadata()
	if err != nil {
		fmt.Printf("Warning: Failed to load interface metadata: %v\n", err)
		metaStore = &InterfaceMetadataStore{Metadata: make(map[string]InterfaceMetadata)}
	}

	configLock.RLock()
	cfg := config
	configLock.RUnlock()

	pfRules := GetPortForwardingRules()

	// 2. Determine Interface Groups
	wanInterfaces := []string{}
	lanInterfaces := []string{}

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

	// Fallback: Auto-detect WAN
	if !hasExplicitWan {
		defWan, err := getDefaultGatewayInterface()
		if err == nil && defWan != "" {
			fmt.Printf("Auto-detected WAN interface: %s\n", defWan)
			wanInterfaces = append(wanInterfaces, defWan)
		}
	}

	// 3. Self-Check: Validate configuration
	if len(wanInterfaces) == 0 {
		return fmt.Errorf("CRITICAL: No WAN interfaces defined. Refusing to apply firewall rules")
	}

	if len(lanInterfaces) == 0 {
		fmt.Println("WARNING: No LAN interfaces labeled. Management access may be limited to localhost only")
	}

	// 4. Generate complete ruleset as text
	ruleset, err := fm.generateFullRuleset(wanInterfaces, lanInterfaces, cfg, pfRules)
	if err != nil {
		return fmt.Errorf("Failed to generate ruleset: %v", err)
	}

	// 5. Snapshot current ruleset for rollback
	snapshot, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		fmt.Printf("Warning: Failed to snapshot current ruleset: %v\n", err)
		snapshot = nil
	}

	// 6. Write ruleset to temp file
	tmpfile, err := os.CreateTemp("", "softrouter-*.nft")
	if err != nil {
		return fmt.Errorf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(ruleset); err != nil {
		return fmt.Errorf("Failed to write ruleset: %v", err)
	}
	tmpfile.Close()

	// 7. Apply atomically via nft -f
	fmt.Printf("Applying ruleset from %s...\n", tmpfile.Name())
	cmd := exec.Command("nft", "-f", tmpfile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("ERROR: Failed to apply ruleset: %v\nOutput: %s\n", err, string(output))

		// Rollback if we have a snapshot
		if snapshot != nil {
			fmt.Println("Attempting rollback...")
			rollbackFile, _ := os.CreateTemp("", "softrouter-rollback-*.nft")
			if rollbackFile != nil {
				rollbackFile.Write(snapshot)
				rollbackFile.Close()
				exec.Command("nft", "-f", rollbackFile.Name()).Run()
				os.Remove(rollbackFile.Name())
				fmt.Println("Rollback completed")
			}
		}

		return fmt.Errorf("Firewall apply failed: %v", err)
	}

	fmt.Println("✓ Firewall rules applied successfully (atomic)")
	return nil
}

// generateFullRuleset creates a complete nftables configuration as text
func (fm *FirewallManager) generateFullRuleset(wanInterfaces, lanInterfaces []string, cfg Config, pfRules []PortForwardingRule) (string, error) {
	var b strings.Builder

	// Flush all existing rules
	b.WriteString("flush ruleset\n\n")

	// ===== INET FILTER TABLE =====
	b.WriteString("table inet softrouter {\n")

	// INPUT Chain - DEFAULT DROP
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority filter; policy drop;\n\n")

	// Accept loopback
	b.WriteString("    iif lo accept\n")

	// Accept established/related
	b.WriteString("    ct state established,related accept\n")

	// Drop invalid
	b.WriteString("    ct state invalid drop\n")

	// Accept ICMP
	b.WriteString("    ip protocol icmp accept\n")
	b.WriteString("    ip6 nexthdr icmpv6 accept\n")

	// Accept SSH (port 22) - prevent lockout
	b.WriteString("    tcp dport 22 accept comment \"SSH access\"\n")

	// Accept all from LAN interfaces
	for _, lan := range lanInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" accept comment \"LAN trust\"\n", lan))
	}

	// Accept DNAT'd connections from WAN (for WebUI access)
	for _, wan := range wanInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" ct status dnat accept comment \"WAN DNAT\"\n", wan))
	}

	// Everything else from WAN is dropped by default policy

	b.WriteString("  }\n\n")

	// FORWARD Chain - DEFAULT DROP
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter; policy drop;\n\n")

	// Accept established/related
	b.WriteString("    ct state established,related accept\n")

	// Allow LAN -> WAN
	for _, lan := range lanInterfaces {
		for _, wan := range wanInterfaces {
			b.WriteString(fmt.Sprintf("    iifname \"%s\" oifname \"%s\" accept comment \"LAN to WAN\"\n", lan, wan))
		}
	}

	// Allow port forwarding (WAN -> LAN via DNAT) - INTERFACE SCOPED
	for _, wan := range wanInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" ct status dnat accept comment \"Port forwarding\"\n", wan))
	}

	b.WriteString("  }\n")
	b.WriteString("}\n\n")

	// ===== IP NAT TABLE =====
	b.WriteString("table ip nat {\n")

	// PREROUTING Chain
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n\n")

	// Port Forwarding Rules
	for _, rule := range pfRules {
		if !rule.Enabled {
			continue
		}
		proto := rule.Protocol
		if proto == "" {
			proto = "tcp"
		}
		dnatTarget := fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort)

		for _, wan := range wanInterfaces {
			b.WriteString(fmt.Sprintf("    iifname \"%s\" %s dport %d dnat to %s comment \"PF: %s\"\n",
				wan, proto, rule.ExternalPort, dnatTarget, rule.Description))
		}
	}

	// WAN Access to WebUI (if enabled)
	if cfg.WebAccess.AllowWAN {
		httpPort := cfg.WebAccess.WANPortHTTP
		if httpPort == 0 {
			httpPort = 980
		}
		httpsPort := cfg.WebAccess.WANPortHTTPS
		if httpsPort == 0 {
			httpsPort = 9443
		}

		targetHTTPS := "443"
		if cfg.TLS.Port != "" {
			targetHTTPS = strings.TrimPrefix(cfg.TLS.Port, ":")
		}

		for _, wan := range wanInterfaces {
			b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport %d dnat to 127.0.0.1:8080 comment \"WAN WebUI HTTP\"\n",
				wan, httpPort))
			b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport %d dnat to 127.0.0.1:%s comment \"WAN WebUI HTTPS\"\n",
				wan, httpsPort, targetHTTPS))
		}
	}

	b.WriteString("  }\n\n")

	// POSTROUTING Chain
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n\n")

	// Masquerade LAN -> WAN
	for _, wan := range wanInterfaces {
		b.WriteString(fmt.Sprintf("    oifname \"%s\" masquerade comment \"NAT\"\n", wan))
	}

	// Hairpin NAT
	if cfg.ProtectedSubnet != "" {
		b.WriteString(fmt.Sprintf("    ip saddr %s ip daddr %s masquerade comment \"Hairpin NAT\"\n",
			cfg.ProtectedSubnet, cfg.ProtectedSubnet))
	}

	b.WriteString("  }\n")
	b.WriteString("}\n")

	return b.String(), nil
}
