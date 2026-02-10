package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// parseMAC parses a MAC address from various formats
// Supports: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, aabbccddeeff
func parseMAC(macAddr string) ([]byte, error) {
	// Remove common separators
	cleaned := strings.ReplaceAll(macAddr, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ToLower(cleaned)

	// Validate format (12 hex characters)
	match, _ := regexp.MatchString("^[0-9a-f]{12}$", cleaned)
	if !match {
		return nil, fmt.Errorf("invalid MAC address format (expected 12 hex characters)")
	}

	// Convert to bytes
	mac, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC address: %w", err)
	}

	if len(mac) != 6 {
		return nil, fmt.Errorf("MAC address must be 6 bytes")
	}

	return mac, nil
}

// SendWakeOnLAN sends a Wake-on-LAN magic packet to the specified MAC address
func SendWakeOnLAN(macAddr string) error {
	// Parse MAC address
	mac, err := parseMAC(macAddr)
	if err != nil {
		return err
	}

	// Build magic packet
	// Format: 6 bytes of 0xFF followed by MAC address repeated 16 times
	packet := make([]byte, 102)

	// Fill first 6 bytes with 0xFF
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}

	// Repeat MAC address 16 times
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], mac)
	}

	// Send UDP broadcast to port 9 (standard WoL port)
	// Also try port 7 as fallback
	for _, port := range []int{9, 7} {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("255.255.255.255:%d", port))
		if err != nil {
			continue
		}

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}

		_, err = conn.Write(packet)
		conn.Close()

		if err == nil {
			fmt.Printf("Wake-on-LAN packet sent to %s (port %d)\n", macAddr, port)
			return nil
		}
	}

	return fmt.Errorf("failed to send Wake-on-LAN packet")
}

// FormatMAC formats a MAC address in standard colon-separated format
func FormatMAC(macAddr string) (string, error) {
	mac, err := parseMAC(macAddr)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), nil
}
