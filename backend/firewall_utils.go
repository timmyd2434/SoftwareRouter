package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// initFirewall sets up the basic networking environment
func initFirewall() {
	fmt.Println("Initializing Firewall...")

	// 1. Enable IP Forwarding
	enableIPForwarding()

	// 2. Setup Basic NFTables Rules (NAT)
	setupNAT()
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

func setupNAT() {
	// We need to apply masquerading to the WAN interface.
	// Since we don't strictly know which is WAN, a common safe default for a router
	// is to masquerade traffic leaving the interface that has the default route.

	wanIface, err := getDefaultGatewayInterface()
	if err != nil {
		fmt.Printf("Warning: Could not determine WAN interface: %v. NAT may not work.\n", err)
		return
	}

	fmt.Printf("Detected WAN Interface: %s. Applying NAT...\n", wanIface)

	// Create table
	exec.Command("nft", "add", "table", "inet", "softrouter").Run()

	// Create chains
	exec.Command("nft", "add", "chain", "inet", "softrouter", "postrouting", "{ type nat hook postrouting priority 100; policy accept; }").Run()
	exec.Command("nft", "add", "chain", "inet", "softrouter", "forward", "{ type filter hook forward priority 0; policy accept; }").Run()

	// Apply Masquerade to WAN
	// rule: oifname "wanIface" masquerade
	cmd := exec.Command("nft", "add", "rule", "inet", "softrouter", "postrouting", "oifname", wanIface, "masquerade")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error applying NAT rule: %v (%s)\n", err, string(output))
	} else {
		fmt.Println("NAT/Masquerading rule applied successfully.")
	}

	// Ensure forwarding is allowed (default policy is often accept, but good to be sure)
	// For now we default to accept all forwarding. In a stricter firewall we'd limit this.
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
