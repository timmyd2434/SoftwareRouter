package main

import (
	"fmt"
	"strings"
)

// ControlPlane provides protection for router management services
// This module generates NFTables rules to rate-limit and protect control plane traffic

// generateControlPlaneRules creates NFT rules for control plane protection.
//
// SECURITY: the previous implementation emitted interface-unfiltered `accept`
// rules for ports 22, 53, 80, 443, 8080 and 9443, which silently re-opened SSH,
// DNS and the WebUI on the WAN and defeated the provisioning/lockdown model.
// LAN access is already granted by the per-interface "LAN trust" rule, and WAN
// WebUI traffic is handled by the explicit `ct status dnat` rule, so the only
// thing worth adding here is a brute-force limiter in front of WAN SSH, and only
// when WAN SSH is actually permitted.
func generateControlPlaneRules(cfg Config, wanInterfaces []string) string {
	var b strings.Builder
	if !(cfg.ProvisioningMode || cfg.AllowWANSSH) {
		return ""
	}
	b.WriteString("  # === CONTROL PLANE PROTECTION (WAN SSH only while permitted) ===\n")
	for _, wan := range wanInterfaces {
		if sanitizeNFTValue(wan) != nil {
			continue
		}
		b.WriteString(fmt.Sprintf("  iifname \"%s\" tcp dport 22 ct state new limit rate over 10/minute burst 20 packets drop comment \"WAN SSH rate limit\"\n", wan))
	}
	b.WriteString("  # === END CONTROL PLANE PROTECTION ===\n\n")
	return b.String()
}

// injectControlPlaneProtectionV2 is used instead of the original V1 implementation.
func injectControlPlaneProtectionV2(ruleset string, cfg Config, wanInterfaces []string) string {
	rules := generateControlPlaneRules(cfg, wanInterfaces)
	if rules == "" {
		return ruleset
	}
	// Strategy: Find "ip6 nexthdr icmpv6 accept" and inject our rules right after it

	marker := "ip6 nexthdr icmpv6 accept"
	if !strings.Contains(ruleset, marker) {
		fmt.Println("[CONTROL_PLANE] WARNING: Could not find injection point in ruleset")
		return ruleset
	}

	// Split on the marker
	parts := strings.SplitN(ruleset, marker, 2)
	if len(parts) != 2 {
		return ruleset
	}

	// Reconstruct with our rules injected
	result := parts[0] + marker + "\n\n" + rules + parts[1]

	fmt.Println("[CONTROL_PLANE] ✓ Control plane protection rules injected")
	return result
}
