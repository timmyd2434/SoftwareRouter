package main

import (
	"fmt"
	"net"
	"strings"
)

// checkIPConflicts is the main entry point for IP conflict detection.
// It should be called before any `ip addr add` operation.
// Returns an error describing the conflict if one is found, nil if safe.
func checkIPConflicts(ipAddress, interfaceName, action string) error {
	// Only check conflicts for "add" actions
	if action != "add" {
		return nil
	}

	// Parse the CIDR
	ip, ipNet, err := net.ParseCIDR(ipAddress)
	if err != nil {
		// Try as plain IP (no CIDR prefix)
		ip = net.ParseIP(ipAddress)
		if ip == nil {
			return fmt.Errorf("invalid IP address format: %s", ipAddress)
		}
		// For a plain IP without prefix, we can't do subnet checks
		// but we can still check for duplicates and reserved addresses
		ipNet = nil
	}

	// Check reserved addresses
	if err := checkReservedAddresses(ip); err != nil {
		return err
	}

	// Check if this exact IP is already assigned to another interface
	if err := checkDuplicateIP(ip, interfaceName); err != nil {
		return err
	}

	// Check for subnet overlap (only possible if we have a CIDR)
	if ipNet != nil {
		if err := checkSubnetOverlap(ipNet, interfaceName); err != nil {
			return err
		}
	}

	return nil
}

// checkReservedAddresses prevents assignment of reserved/special IP addresses
// that would cause network problems.
func checkReservedAddresses(ip net.IP) error {
	// Normalize to 4-byte form for IPv4
	ip4 := ip.To4()

	if ip4 != nil {
		// IPv4 checks
		if ip4.Equal(net.IPv4zero) {
			return fmt.Errorf("cannot assign 0.0.0.0 (unspecified address)")
		}
		if ip4.Equal(net.IPv4bcast) {
			return fmt.Errorf("cannot assign 255.255.255.255 (broadcast address)")
		}
		// Check for 127.x.x.x loopback range
		if ip4[0] == 127 {
			return fmt.Errorf("cannot assign loopback address %s to a physical interface", ip.String())
		}
	} else {
		// IPv6 checks
		if ip.Equal(net.IPv6zero) {
			return fmt.Errorf("cannot assign :: (unspecified address)")
		}
		if ip.Equal(net.IPv6loopback) {
			return fmt.Errorf("cannot assign ::1 (loopback address) to a physical interface")
		}
	}

	return nil
}

// checkDuplicateIP checks if the exact IP address is already assigned to
// a different interface on the system.
func checkDuplicateIP(ip net.IP, excludeIface string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to enumerate network interfaces: %v", err)
	}

	for _, iface := range ifaces {
		// Skip the interface we're configuring
		if iface.Name == excludeIface {
			continue
		}
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			existingIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			if existingIP.Equal(ip) {
				return fmt.Errorf("IP address %s is already assigned to interface %s", ip.String(), iface.Name)
			}
		}
	}

	return nil
}

// checkSubnetOverlap checks if the new IP's subnet overlaps with any existing
// interface subnet. Overlapping subnets on different interfaces cause routing
// ambiguity and can lead to complete loss of network connectivity.
func checkSubnetOverlap(newNet *net.IPNet, excludeIface string) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to enumerate network interfaces: %v", err)
	}

	for _, iface := range ifaces {
		// Skip the interface we're configuring
		if iface.Name == excludeIface {
			continue
		}
		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			_, existingNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// Two networks overlap if either contains the other's network address
			if subnetsOverlap(newNet, existingNet) {
				return fmt.Errorf(
					"subnet %s overlaps with existing subnet %s on interface %s — "+
						"this would cause routing ambiguity and likely kill network connectivity",
					newNet.String(), existingNet.String(), iface.Name,
				)
			}
		}
	}

	return nil
}

// subnetsOverlap returns true if two IP networks overlap.
// Two networks overlap if either one contains the network address of the other,
// OR if they share any common address space.
func subnetsOverlap(a, b *net.IPNet) bool {
	// Ensure we're comparing the same IP family
	aIP4 := a.IP.To4()
	bIP4 := b.IP.To4()

	if (aIP4 != nil) != (bIP4 != nil) {
		// Different IP families can't overlap
		return false
	}

	return a.Contains(b.IP) || b.Contains(a.IP)
}

// checkManagementIPConflict checks if assigning this IP would disrupt
// the management connection. This is detected by checking if the new subnet
// would overlap with interfaces labeled as "LAN" or "Management" in the
// interface metadata.
func checkManagementIPConflict(ip net.IP, ipNet *net.IPNet, excludeIface string) error {
	if ipNet == nil {
		return nil
	}

	// Load interface metadata to find management/LAN interfaces
	metaStore, err := loadInterfaceMetadata()
	if err != nil {
		// If we can't load metadata, skip this check (don't block operations)
		return nil
	}

	for ifaceName, meta := range metaStore.Metadata {
		if ifaceName == excludeIface {
			continue
		}

		label := strings.ToLower(meta.Label)
		if label != "lan" && label != "management" {
			continue
		}

		// Get the actual IP addresses on this management interface
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			_, existingNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			if subnetsOverlap(ipNet, existingNet) {
				return fmt.Errorf(
					"CRITICAL: subnet %s conflicts with %s interface %s (subnet %s) — "+
						"assigning this address would likely sever your management connection to the router",
					ipNet.String(), meta.Label, ifaceName, existingNet.String(),
				)
			}
		}
	}

	return nil
}
