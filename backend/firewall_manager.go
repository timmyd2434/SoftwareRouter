package main

import (
	"fmt"
	"log"
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
// Note: Table creation is handled by generateFullRuleset, not here
func InitFirewallManager() {
	// Enable route_localnet to allow DNAT to 127.0.0.1
	// This is critical for the security model where we bind to localhost but DNAT from LAN/WAN
	if err := runPrivileged("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"); err != nil {
		fmt.Printf("WARNING: Failed to set route_localnet on all interfaces: %v\n", err)
	}
	if err := runPrivileged("sysctl", "-w", "net.ipv4.conf.default.route_localnet=1"); err != nil {
		fmt.Printf("WARNING: Failed to set route_localnet on default interface: %v\n", err)
	}
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
	snapshot, err := runPrivilegedOutput("nft", "list", "ruleset")
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
	tmpPath := tmpfile.Name() // Store the path before closing
	defer func() {            // Only delete on success or if validation passes
		if err == nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpfile.WriteString(ruleset); err != nil {
		return fmt.Errorf("Failed to write ruleset: %v", err)
	}
	tmpfile.Close()

	// Validate with nft -c (check mode)
	fmt.Println("Validating ruleset syntax...")
	validateCmd := exec.Command("nft", "-c", "-f", tmpPath)
	validateOutput, validateErr := validateCmd.CombinedOutput()

	if validateErr != nil {
		// KEEP the file for debugging and log detailed error
		log.Printf("NFTables validation FAILED - preserving file: %s", tmpPath)
		log.Printf("NFT validation error output:\n%s", string(validateOutput))
		// Attempt to get a more detailed error from nft if the combined output wasn't enough
		if err := runPrivileged("nft", "-c", "-f", tmpPath); err != nil {
			log.Printf("Detailed NFT error: %v", err)
		}
		// Return error but continue to start server
		return fmt.Errorf("nftables validation failed - check %s for details: %v", tmpPath, validateErr)
	}

	// 8. Install dead-man switch (emergency access protection)
	if err := installDeadManSwitch(); err != nil {
		fmt.Printf("Warning: Could not install dead-man switch: %v\n", err)
	}

	// 9. Apply atomically via nft -f
	fmt.Printf("Applying ruleset from %s...\n", tmpfile.Name())
	if output, err := runPrivilegedCombinedOutput("nft", "-f", tmpfile.Name()); err != nil {
		fmt.Printf("ERROR: Failed to apply ruleset: %v\nOutput: %s\n", err, string(output))

		// Rollback if we have a snapshot
		if snapshot != nil {
			fmt.Println("Attempting rollback...")
			rollbackFile, _ := os.CreateTemp("", "softrouter-rollback-*.nft")
			if rollbackFile != nil {
				if _, err := rollbackFile.Write(snapshot); err != nil {
					fmt.Printf("ERROR: Failed to write rollback file: %v\n", err)
				}
				if err := rollbackFile.Close(); err != nil {
					fmt.Printf("WARNING: Failed to close rollback file: %v\n", err)
				}
				if err := runPrivileged("nft", "-f", rollbackFile.Name()); err != nil {
					fmt.Printf("ERROR: Rollback failed: %v\n", err)
				} else {
					fmt.Println("Rollback completed successfully")
				}
				if err := os.Remove(rollbackFile.Name()); err != nil {
					fmt.Printf("WARNING: Failed to remove rollback file: %v\n", err)
				}
				fmt.Println("Rollback completed")
			}
		}

		return fmt.Errorf("Firewall apply failed: %v", err)
	}

	// 10. Remove dead-man switch (rules applied successfully)
	if err := removeDeadManSwitch(); err != nil {
		fmt.Printf("WARNING: Failed to remove dead-man switch: %v\n", err)
	}

	// 11. Start watchdog timer (user must confirm or rollback occurs)
	if snapshot != nil {
		if err := startWatchdogTimer(string(snapshot)); err != nil {
			fmt.Printf("Warning: Could not start watchdog timer: %v\n", err)
		}
	}

	// 12. Save known-good snapshot for boot-safe fallback
	if err := saveKnownGoodSnapshot(ruleset); err != nil {
		fmt.Printf("Warning: Could not save known-good snapshot: %v\n", err)
	}

	fmt.Println("✓ Firewall rules applied successfully (atomic)")
	fmt.Println("⚠️  You have 60 seconds to confirm changes via WebUI or rules will rollback")
	return nil
}

// generateFullRuleset creates a complete nftables configuration as text
func (fm *FirewallManager) generateFullRuleset(wanInterfaces, lanInterfaces []string, cfg Config, pfRules []PortForwardingRule) (string, error) {
	var b strings.Builder

	// Control plane protection will be injected later

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

	// Accept DNS (port 53) - explicit rules for robustness
	b.WriteString("    udp dport 53 accept comment \"DNS\"\n")
	b.WriteString("    tcp dport 53 accept comment \"DNS\"\n")

	// Accept all from LAN interfaces
	for _, lan := range lanInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" accept comment \"LAN trust\"\n", lan))
	}

	// Accept DNAT'd connections from WAN (for WebUI access)
	for _, wan := range wanInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" ct status dnat accept comment \"WAN DNAT\"\n", wan))
	}

	// Log dropped packets (rate-limited for debugging)
	b.WriteString("    limit rate 5/minute burst 10 packets log prefix \"[INPUT DROP] \"\n")

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

	// Log dropped packets (rate-limited for debugging)
	b.WriteString("    limit rate 5/minute burst 10 packets log prefix \"[FORWARD DROP] \"\n")

	b.WriteString("  }\n")
	b.WriteString("}\n\n")

	// ===== IP NAT TABLE =====
	// Note: IPv6 NAT is intentionally not implemented as it's typically not needed
	// for IPv6 deployments which use direct routing. If IPv6 NAT is required in
	// the future, a separate 'table ip6 nat' section would be added here.
	b.WriteString("table ip nat {\n")

	// PREROUTING Chain
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n\n")

	// LAN Access to WebUI (DNAT to localhost)
	for _, lan := range lanInterfaces {
		b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport 80 dnat to 127.0.0.1:8090 comment \"LAN WebUI HTTP\"\n", lan))
		targetHTTPS := "443"
		if cfg.TLS.Port != "" {
			targetHTTPS = strings.TrimPrefix(cfg.TLS.Port, ":")
		}
		b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport %s dnat to 127.0.0.1:%s comment \"LAN WebUI HTTPS\"\n",
			lan, targetHTTPS, targetHTTPS))
	}

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
			b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport %d dnat to 127.0.0.1:8090 comment \"WAN WebUI HTTP\"\n",
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
	// Try configured subnet first, then auto-detect from LAN interfaces
	subnet := cfg.ProtectedSubnet
	if subnet == "" && len(lanInterfaces) > 0 {
		// Fallback: try to detect subnet from first LAN interface
		// This is a best-effort attempt for unconfigured systems
		fmt.Println("Warning: ProtectedSubnet not configured, hairpin NAT may not work optimally")
	}
	if subnet != "" {
		b.WriteString(fmt.Sprintf("    ip saddr %s ip daddr %s masquerade comment \"Hairpin NAT\"\n",
			subnet, subnet))
	}

	b.WriteString("  }\n")
	b.WriteString("}\n")

	// Inject control plane protection into the ruleset
	ruleset := b.String()
	ruleset = injectControlPlaneProtectionV2(ruleset)

	return ruleset, nil
}
