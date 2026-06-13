package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

const firstBootFlagFile = "/etc/softrouter/first_boot_complete"

// isFirstBoot checks if this is the first time the system is booting
func isFirstBoot() bool {
	_, err := os.Stat(firstBootFlagFile)
	return os.IsNotExist(err)
}

// markFirstBootComplete creates the flag file to indicate first boot is done
func markFirstBootComplete() error {
	// Ensure directory exists
	if err := os.MkdirAll("/etc/softrouter", 0750); err != nil {
		return err
	}
	return os.WriteFile(firstBootFlagFile, []byte("1"), 0600)
}

// needsWANConfiguration checks if any interface is explicitly labeled as WAN
// Returns true if no WAN interfaces are configured (requires setup)
func needsWANConfiguration() bool {
	metaStore, err := loadInterfaceMetadata()
	if err != nil {
		return true // If we can't load metadata, assume setup needed
	}

	// Check if any interface has WAN label
	for _, meta := range metaStore.Metadata {
		if strings.EqualFold(meta.Label, "WAN") {
			return false
		}
	}

	return true
}

// ensureFallbackNetwork checks if any non-loopback interface has an IPv4 address.
// If none are found, it temporarily configures the first physical interface with
// a fallback static IP and starts a temporary DHCP server.
func ensureFallbackNetwork() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("FallbackNetwork: Error getting interfaces: %v", err)
		return
	}

	var fallbackIface *net.Interface
	hasIPv4 := false

	// Check for existing IPv4 configurations and find a suitable fallback interface
	for _, i := range ifaces {
		// Skip loopback interfaces
		if (i.Flags & net.FlagLoopback) != 0 {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		// Check if it has an IPv4 address
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					log.Printf("FallbackNetwork: Found existing IPv4 address %s on interface %s", ipnet.IP.String(), i.Name)
					hasIPv4 = true
					break
				}
			}
		}

		// Candidate for fallback (physical interface typically starts with en or eth)
		// We'll just take the first non-loopback one if we haven't found a better one
		if fallbackIface == nil && !strings.HasPrefix(i.Name, "lo") && !strings.HasPrefix(i.Name, "wg") && !strings.HasPrefix(i.Name, "tun") && !strings.Contains(i.Name, "vlan") {
			// Need to create a copy of the loop variable to take its address
			candidate := i
			fallbackIface = &candidate
		}
	}

	// If any interface has an IPv4 address, we assume the system is reachable
	if hasIPv4 {
		return
	}

	if fallbackIface == nil {
		log.Println("FallbackNetwork: No suitable interface found for fallback network")
		return
	}

	log.Printf("FallbackNetwork: No IPv4 addresses detected. Applying temporary fallback config to %s", fallbackIface.Name)

	// 1. Assign 192.168.254.1/24
	fallbackIP := "192.168.254.1/24"
	if output, err := runPrivilegedCombinedOutput("ip", "addr", "add", fallbackIP, "dev", fallbackIface.Name); err != nil {
		log.Printf("FallbackNetwork: Failed to assign IP: %v, output: %s", err, string(output))
		// We might fail if it's already there or other errors, continue anyway just in case
	}

	// 2. Bring interface UP
	if output, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", fallbackIface.Name, "up"); err != nil {
		log.Printf("FallbackNetwork: Failed to bring interface up: %v, output: %s", err, string(output))
	}

	// 3. Start temporary dnsmasq
	dnsmasqConf := fmt.Sprintf(`interface=%s
dhcp-range=192.168.254.100,192.168.254.200,12h
dhcp-option=3,192.168.254.1
dhcp-option=6,192.168.254.1
`, fallbackIface.Name)

	confPath := "/tmp/fallback-dnsmasq.conf"
	pidPath := "/tmp/fallback-dnsmasq.pid"

	if err := os.WriteFile(confPath, []byte(dnsmasqConf), 0600); err != nil {
		log.Printf("FallbackNetwork: Failed to write temporary dnsmasq config: %v", err)
		return
	}

	// Kill any existing fallback dnsmasq just in case
	_ = runPrivileged("pkill", "-F", pidPath)

	if err := runPrivileged("dnsmasq", "-C", confPath, "-x", pidPath); err != nil {
		log.Printf("FallbackNetwork: Failed to start temporary dnsmasq: %v", err)
		return
	}

	log.Println("FallbackNetwork: Temporary network initialized at 192.168.254.1 (DHCP: 192.168.254.100-200)")
}
