package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// FirewallAlias represents a named group of IPs, networks, or ports
type FirewallAlias struct {
	Name        string   `json:"name"`        // e.g., "TRUSTED_SERVERS" (uppercase, underscores)
	Type        string   `json:"type"`        // "ip", "network", "port"
	Values      []string `json:"values"`      // e.g., ["192.168.1.10", "192.168.1.20"]
	Description string   `json:"description"` // User-friendly description
}

// AliasStore holds all firewall aliases
type AliasStore struct {
	Aliases []FirewallAlias `json:"aliases"`
}

const aliasConfigPath = "/etc/softrouter/firewall_aliases.json"

// loadFirewallAliases loads aliases from disk
func loadFirewallAliases() (*AliasStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(aliasConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(aliasConfigPath); os.IsNotExist(err) {
		// Return empty store if file doesn't exist
		return &AliasStore{Aliases: []FirewallAlias{}}, nil
	}

	data, err := os.ReadFile(aliasConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read aliases file: %w", err)
	}

	var store AliasStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse aliases JSON: %w", err)
	}

	return &store, nil
}

// saveFirewallAliases saves aliases to disk
func saveFirewallAliases(store *AliasStore) error {
	// Ensure directory exists
	dir := filepath.Dir(aliasConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal aliases: %w", err)
	}

	if err := os.WriteFile(aliasConfigPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write aliases file: %w", err)
	}

	return nil
}

// validateAliasName checks if alias name is valid (uppercase, numbers, underscores)
func validateAliasName(name string) error {
	if name == "" {
		return fmt.Errorf("alias name cannot be empty")
	}

	// NFTables requires variable names to be uppercase with underscores
	match, _ := regexp.MatchString("^[A-Z][A-Z0-9_]*$", name)
	if !match {
		return fmt.Errorf("alias name must start with uppercase letter and contain only uppercase letters, numbers, and underscores")
	}

	return nil
}

// validateIPAddress validates an IPv4 or IPv6 address
func validateIPAddress(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// validateNetwork validates a CIDR network notation
func validateNetwork(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %s", cidr)
	}
	return nil
}

// validatePort validates a port number or port range
func validatePort(port string) error {
	// Check if it's a range (e.g., "80-443")
	if strings.Contains(port, "-") {
		parts := strings.Split(port, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range format: %s (use startPort-endPort)", port)
		}

		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))

		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid port numbers in range: %s", port)
		}

		if start < 1 || start > 65535 || end < 1 || end > 65535 {
			return fmt.Errorf("port numbers must be between 1 and 65535")
		}

		if start >= end {
			return fmt.Errorf("start port must be less than end port in range")
		}

		return nil
	}

	// Single port
	portNum, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return fmt.Errorf("invalid port number: %s", port)
	}

	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("port number must be between 1 and 65535")
	}

	return nil
}

// validateAlias validates an entire alias
func validateAlias(alias FirewallAlias) error {
	// Validate name
	if err := validateAliasName(alias.Name); err != nil {
		return err
	}

	// Validate type
	validTypes := map[string]bool{"ip": true, "network": true, "port": true}
	if !validTypes[alias.Type] {
		return fmt.Errorf("invalid alias type: %s (must be ip, network, or port)", alias.Type)
	}

	// Validate values exist
	if len(alias.Values) == 0 {
		return fmt.Errorf("alias must have at least one value")
	}

	// Type-specific validation
	for _, value := range alias.Values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue // Skip empty values
		}

		switch alias.Type {
		case "ip":
			if err := validateIPAddress(value); err != nil {
				return err
			}
		case "network":
			if err := validateNetwork(value); err != nil {
				return err
			}
		case "port":
			if err := validatePort(value); err != nil {
				return err
			}
		}
	}

	return nil
}

// generateAliasDefines generates nftables define statements
func generateAliasDefines(aliases []FirewallAlias) string {
	if len(aliases) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("# Firewall Aliases\n")

	for _, alias := range aliases {
		// Filter out empty values
		validValues := []string{}
		for _, v := range alias.Values {
			v = strings.TrimSpace(v)
			if v != "" {
				validValues = append(validValues, v)
			}
		}

		if len(validValues) == 0 {
			continue
		}

		// Create set notation for multiple values
		var valueStr string
		if len(validValues) == 1 {
			valueStr = validValues[0]
		} else {
			valueStr = fmt.Sprintf("{ %s }", strings.Join(validValues, ", "))
		}

		// Add comment if description exists
		comment := ""
		if alias.Description != "" {
			comment = fmt.Sprintf(" # %s", alias.Description)
		}

		b.WriteString(fmt.Sprintf("define %s = %s%s\n", alias.Name, valueStr, comment))
	}

	b.WriteString("\n")
	return b.String()
}
