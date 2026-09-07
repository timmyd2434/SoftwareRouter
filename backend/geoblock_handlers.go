package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// validCountryCode matches exactly 2 ASCII letters (case-insensitive)
// SECURITY: Prevents injection via country code query param in curl arguments
var validCountryCode = regexp.MustCompile(`^[A-Za-z]{2}$`)

// handleGetGeoBlockingConfig returns the current geoblocking configuration
func handleGetGeoBlockingConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg, err := loadGeoBlockingConfig()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to load geoblocking config", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// handleUpdateGeoBlockingConfig updates the geoblocking configuration
func handleUpdateGeoBlockingConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg GeoBlockingConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		respondInvalidRequest(w, "Invalid request body")
		return
	}

	// Validate configuration
	if err := validateGeoBlockingConfig(&cfg); err != nil {
		respondInvalidRequest(w, "Invalid configuration")
		return
	}

	// Only ensure IP lists exist when geoblocking is actually being enabled with countries.
	// Skip this when disabling — we don't need the IP lists to flush the rules, and a
	// download failure should never prevent a user from turning geoblocking OFF.
	if cfg.Enabled && len(cfg.BlockedCountries) > 0 {
		for _, country := range cfg.BlockedCountries {
			if err := ensureCountryIPList(country); err != nil {
				respondSystemError(w, ErrGenericInternalError, fmt.Sprintf("Failed to get IP list for %s", country), err)
				return
			}
		}
	}

	// Save configuration
	if err := saveGeoBlockingConfig(&cfg); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save config", err)
		return
	}

	if !cfg.Enabled {
		// When DISABLING: explicitly delete every geoblocking rule by handle first.
		// This is a direct, targeted removal that does not rely on flush ruleset.
		// We do this BEFORE the full regeneration so rules are gone immediately even
		// if the regeneration step encounters an unrelated failure.
		fmt.Println("GeoBlocking disabled — explicitly removing geoblocking rules by handle...")
		if err := flushGeoBlockingRules(); err != nil {
			fmt.Printf("Warning: flushGeoBlockingRules error: %v\n", err)
			// Still attempt full regeneration below — don't bail out yet
		} else {
			fmt.Println("✓ Geoblocking rules removed by handle")
		}

		// Regenerate the full ruleset so the saved snapshot and /etc/nftables.conf
		// are consistent (no geo rules at next boot).
		if err := firewallManager.ApplyFirewallRules(true); err != nil {
			fmt.Printf("Warning: ApplyFirewallRules after geo-disable: %v\n", err)
			// The direct deletion above already removed the rules from the kernel,
			// so we return success even if the full regeneration failed.
		}
	} else {
		// When ENABLING: generate and apply the full ruleset with geo rules.
		if err := firewallManager.ApplyFirewallRules(true); err != nil {
			respondSystemError(w, ErrGenericInternalError, "Geoblocking config saved but firewall rules could not be applied", err)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Geoblocking configuration updated",
	})
}

// handleDownloadCountryIPList manually downloads IP list for a country
func handleDownloadCountryIPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	countryCode := r.URL.Query().Get("country")
	if countryCode == "" {
		http.Error(w, "Country code is required", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate country code format to prevent injection via curl arguments
	if !validCountryCode.MatchString(countryCode) {
		http.Error(w, "Invalid country code: must be exactly 2 letters", http.StatusBadRequest)
		return
	}

	if err := downloadCountryIPList(countryCode); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to download IP list", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP list for %s downloaded", countryCode),
	})
}
