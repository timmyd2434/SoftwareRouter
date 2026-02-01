package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// initFirewall sets up the basic networking environment
// NOTE: This function ONLY handles sysctl settings.
// All nftables/firewall logic is now handled by FirewallManager.
func initFirewall() {
	fmt.Println("Initializing basic networking (sysctl only)...")

	// Enable IP Forwarding
	enableIPForwarding()

	// Note: NAT, firewall rules, and all nftables configuration
	// is now exclusively managed by FirewallManager.ApplyFirewallRules()
}

func enableIPForwarding() {
	// Enable IPv4 forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error enabling IP forwarding: %v\n", err)
	} else {
		fmt.Println("IP Forwarding enabled.")
	}
}

// setupNAT is deprecated - all NAT logic moved to FirewallManager
// Keeping as stub in case of external references
func setupNAT() {
	fmt.Println("setupNAT() is deprecated - NAT configuration handled by FirewallManager")
}

func getDefaultGatewayInterface() (string, error) {
	// Use 'ip route list 0/0' to find the default route
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Output looks like: "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100"
	parts := strings.Fields(string(output))
	for i, part := range parts {
		if part == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}

	return "", fmt.Errorf("no default route found")
}
