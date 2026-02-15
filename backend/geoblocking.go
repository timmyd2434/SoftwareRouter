package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GeoBlockingConfig represents the geoblocking configuration
type GeoBlockingConfig struct {
	Enabled          bool     `json:"enabled"`          // Master switch
	BlockedCountries []string `json:"blockedCountries"` // ISO codes: ["CN", "RU", "KP"]
	AllowPrivateIPs  bool     `json:"allowPrivateIPs"`  // Don't block RFC1918 addresses
	Mode             string   `json:"mode"`             // "blocklist" or "allowlist"
}

const (
	geoBlockingConfigPath = "/etc/softrouter/geoblocking.json"
	countryIPListsDir     = "/etc/softrouter/country-ip-lists"
)

// loadGeoBlockingConfig loads geoblocking configuration from disk
func loadGeoBlockingConfig() (*GeoBlockingConfig, error) {
	// Ensure directory exists
	dir := filepath.Dir(geoBlockingConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(geoBlockingConfigPath); os.IsNotExist(err) {
		// Return default config if file doesn't exist
		return &GeoBlockingConfig{
			Enabled:          false,
			BlockedCountries: []string{},
			AllowPrivateIPs:  true,
			Mode:             "blocklist",
		}, nil
	}

	data, err := os.ReadFile(geoBlockingConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg GeoBlockingConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return &cfg, nil
}

// saveGeoBlockingConfig saves geoblocking configuration to disk
func saveGeoBlockingConfig(cfg *GeoBlockingConfig) error {
	// Ensure directory exists
	dir := filepath.Dir(geoBlockingConfigPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(geoBlockingConfigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// validateGeoBlockingConfig validates the configuration
func validateGeoBlockingConfig(cfg *GeoBlockingConfig) error {
	if cfg.Mode != "blocklist" && cfg.Mode != "allowlist" {
		return fmt.Errorf("invalid mode: must be 'blocklist' or 'allowlist'")
	}

	// Validate country codes (must be 2-letter uppercase)
	for _, code := range cfg.BlockedCountries {
		if len(code) != 2 {
			return fmt.Errorf("invalid country code '%s': must be 2 letters", code)
		}
		if code != strings.ToUpper(code) {
			return fmt.Errorf("invalid country code '%s': must be uppercase", code)
		}
	}

	return nil
}

// getCountryIPListPath returns the path to a country's IP list file
func getCountryIPListPath(countryCode string) string {
	return filepath.Join(countryIPListsDir, fmt.Sprintf("%s.txt", strings.ToUpper(countryCode)))
}

// loadCountryIPList loads IP ranges for a country from disk
func loadCountryIPList(countryCode string) ([]string, error) {
	path := getCountryIPListPath(countryCode)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read IP list for %s: %w", countryCode, err)
	}

	// Parse line by line
	lines := strings.Split(string(data), "\n")
	ipRanges := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ipRanges = append(ipRanges, line)
	}

	return ipRanges, nil
}

// downloadCountryIPList downloads IP ranges for a country from public source
func downloadCountryIPList(countryCode string) error {
	// Ensure directory exists
	if err := os.MkdirAll(countryIPListsDir, 0755); err != nil {
		return fmt.Errorf("failed to create IP lists directory: %w", err)
	}

	code := strings.ToUpper(countryCode)
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone", strings.ToLower(code))

	fmt.Printf("Downloading IP list for %s from %s\n", code, url)

	// Download using curl via privileged executor (allowlist-controlled)
	if err := runPrivileged("curl", "-f", "-s", "-L", "-o", getCountryIPListPath(code), url); err != nil {
		return fmt.Errorf("failed to download IP list for %s: %w", code, err)
	}

	fmt.Printf("Downloaded IP list for %s\n", code)
	return nil
}

// ensureCountryIPList ensures IP list for country exists, downloading if needed
func ensureCountryIPList(countryCode string) error {
	path := getCountryIPListPath(countryCode)

	// Check if file exists
	if _, err := os.Stat(path); err == nil {
		// File exists
		return nil
	}

	// Download it
	return downloadCountryIPList(countryCode)
}
