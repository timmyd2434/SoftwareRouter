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

	// Ensure IP lists exist for all blocked countries
	for _, country := range cfg.BlockedCountries {
		if err := ensureCountryIPList(country); err != nil {
			respondSystemError(w, ErrGenericInternalError, fmt.Sprintf("Failed to get IP list for %s", country), err)
			return
		}
	}

	// Save configuration
	if err := saveGeoBlockingConfig(&cfg); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save config", err)
		return
	}

	// Apply firewall rules if enabled
	if cfg.Enabled {
		if err := firewallManager.ApplyFirewallRules(); err != nil {
			fmt.Printf("Warning: Failed to apply firewall rules after geoblocking update: %v\n", err)
			// Don't fail the request - config is saved
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
