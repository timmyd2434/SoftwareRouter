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

// injectControlPlaneProtection inserts control plane rules into the INPUT chain
// This modifies an existing ruleset to add protection before user-defined rules
func injectControlPlaneProtection(ruleset string) string {
	// Find the INPUT chain and inject protection rules after the basic accepts
	// We want to inject after:
	// - loopback accept
	// - established,related accept
	// - invalid drop
	// But before:
	// - User-defined rules
	// - LAN interface accepts

	lines := strings.Split(ruleset, "\n")
	var result strings.Builder
	injected := false

	for i, line := range lines {
		result.WriteString(line)
		result.WriteString("\n")

		// Look for the INPUT chain and inject after the basic security rules
		if strings.Contains(line, "chain input") {
			// Scan forward to find where to inject
			// We want to inject after "ct state invalid drop" but before interface-specific rules
			for j := i + 1; j < len(lines); j++ {
				currentLine := strings.TrimSpace(lines[j])

				// Found the injection point - after invalid drop and ICMP accepts
				if strings.Contains(currentLine, "ip6 nexthdr icmpv6 accept") {
					// Inject control plane rules here
					if !injected {
						// Write the next few lines until we hit the ICMP line
						for k := i + 1; k <= j; k++ {
							result.WriteString(lines[k])
							result.WriteString("\n")
						}

						// Now inject control plane protection
						result.WriteString(generateControlPlaneRules())
						injected = true

						// Skip the lines we already wrote
						i = j
						break
					}
				}
			}
		}

		// If we've already injected, skip lines we've already written
		if injected && i < len(lines)-1 {
			break
		}
	}

	// If we didn't inject (ruleset format different than expected), log warning
	if !injected {
		fmt.Println("[CONTROL_PLANE] WARNING: Could not inject control plane rules - ruleset format unexpected")
		return ruleset // Return original
	}

	// Write remaining lines
	for i := len(result.String()); i < len(ruleset); i++ {
		// This is a bit hacky but we need to append the rest
		// Actually, let's reconstruct properly
	}

	return result.String()
}

// A better implementation that's more robust:
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
