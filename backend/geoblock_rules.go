package main

import (
	"fmt"
	"strings"
)

// generateGeoBlockingDefines generates nftables define statements for blocked countries
func generateGeoBlockingDefines(cfg *GeoBlockingConfig) (string, error) {
	if !cfg.Enabled || len(cfg.BlockedCountries) == 0 {
		return "", nil
	}

	var b strings.Builder
	b.WriteString("# GeoBlocking IP Sets\n")

	for _, country := range cfg.BlockedCountries {
		// Load IP ranges for this country
		ipRanges, err := loadCountryIPList(country)
		if err != nil {
			return "", fmt.Errorf("failed to load IP list for %s: %w", country, err)
		}

		if len(ipRanges) == 0 {
			continue
		}

		// Create define for this country
		// Split into chunks if too large (nftables has limits)
		chunkSize := 1000
		for i := 0; i < len(ipRanges); i += chunkSize {
			end := i + chunkSize
			if end > len(ipRanges) {
				end = len(ipRanges)
			}

			chunk := ipRanges[i:end]
			chunkNum := i/chunkSize + 1
			defineName := fmt.Sprintf("GEOBLOCK_%s_%d", country, chunkNum)

			b.WriteString(fmt.Sprintf("define %s = { %s }\n",
				defineName,
				strings.Join(chunk, ", ")))
		}
	}

	b.WriteString("\n")
	return b.String(), nil
}

// generateGeoBlockingRules generates nftables rules for geoblocking
func generateGeoBlockingRules(cfg *GeoBlockingConfig) string {
	if !cfg.Enabled || len(cfg.BlockedCountries) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("    # GeoBlocking Rules\n")

	if cfg.AllowPrivateIPs {
		// Allow private IP ranges (RFC1918)
		b.WriteString("    ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept comment \"Allow private IPs\"\n")
		b.WriteString("    ip6 saddr { fc00::/7, fe80::/10 } accept comment \"Allow private IPv6\"\n")
	}

	// Generate drop rules for each blocked country
	for _, country := range cfg.BlockedCountries {
		// Load IP count to determine number of chunks
		ipRanges, err := loadCountryIPList(country)
		if err != nil || len(ipRanges) == 0 {
			continue
		}

		chunkSize := 1000
		numChunks := (len(ipRanges) + chunkSize - 1) / chunkSize

		for i := 1; i <= numChunks; i++ {
			defineName := fmt.Sprintf("GEOBLOCK_%s_%d", country, i)

			if cfg.Mode == "blocklist" {
				b.WriteString(fmt.Sprintf("    ip saddr $%s drop comment \"Block %s\"\n", defineName, country))
			} else {
				// Allowlist mode - accept these countries, drop others later
				b.WriteString(fmt.Sprintf("    ip saddr $%s accept comment \"Allow %s\"\n", defineName, country))
			}
		}
	}

	// In allowlist mode, drop everything else
	if cfg.Mode == "allowlist" {
		b.WriteString("    drop comment \"Block all except allowlist\"\n")
	}

	b.WriteString("\n")
	return b.String()
}
