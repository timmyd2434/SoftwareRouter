package main

import (
	"fmt"
	"strings"
)

// ControlPlane provides protection for router management services
// This module generates NFTables rules to rate-limit and protect control plane traffic

// generateControlPlaneRules creates NFT rules for control plane protection
// These rules are injected early in the INPUT chain to rate-limit management access
func generateControlPlaneRules() string {
	var b strings.Builder

	b.WriteString("  # === CONTROL PLANE PROTECTION ===\n")
	b.WriteString("  # Rate-limit management services to prevent DoS\n")
	b.WriteString("  # These rules protect SSH, WebUI, and API access\n\n")

	// SSH Rate Limiting
	b.WriteString("  # SSH rate limiting: max 10 new connections per minute per source\n")
	b.WriteString("  tcp dport 22 ct state new limit rate 10/minute burst 20 packets accept comment \"SSH rate limit\"\n")
	b.WriteString("  # Note: Existing connections always allowed by earlier established,related rule\n\n")

	// WebUI HTTP Rate Limiting
	b.WriteString("  # WebUI HTTP rate limiting: max 100 new connections per minute per source\n")
	b.WriteString("  tcp dport 8090 ct state new limit rate 100/minute burst 50 packets accept comment \"WebUI HTTP rate limit\"\n")
	b.WriteString("  tcp dport 80 ct state new limit rate 100/minute burst 50 packets accept comment \"WebUI HTTP rate limit\"\n\n")

	// WebUI HTTPS Rate Limiting
	b.WriteString("  # WebUI HTTPS rate limiting: max 100 new connections per minute per source\n")
	b.WriteString("  tcp dport 443 ct state new limit rate 100/minute burst 50 packets accept comment \"WebUI HTTPS rate limit\"\n")
	b.WriteString("  tcp dport 9443 ct state new limit rate 100/minute burst 50 packets accept comment \"WebUI HTTPS rate limit\"\n\n")

	// DNS Rate Limiting (protect local DNS resolver)
	b.WriteString("  # DNS rate limiting: max 60 queries per second per source\n")
	b.WriteString("  udp dport 53 limit rate 60/second burst 100 packets accept comment \"DNS rate limit\"\n")
	b.WriteString("  tcp dport 53 limit rate 60/second burst 100 packets accept comment \"DNS rate limit\"\n\n")

	b.WriteString("  # === END CONTROL PLANE PROTECTION ===\n\n")

	return b.String()
}

// injectControlPlaneProtectionV2 is used instead of the original V1 implementation.
func injectControlPlaneProtectionV2(ruleset string) string {
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
	result := parts[0] + marker + "\n\n" + generateControlPlaneRules() + parts[1]

	fmt.Println("[CONTROL_PLANE] ✓ Control plane protection rules injected")
	return result
}
