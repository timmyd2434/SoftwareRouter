package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RAConfigRequest represents a request to configure Router Advertisement
type RAConfigRequest struct {
	Interface  string   `json:"interface"`
	Enabled    bool     `json:"enabled"`
	Prefix     string   `json:"prefix"`     // e.g., "2001:db8::/64"
	DNSServers []string `json:"dnsServers"` // Optional DNS servers
}

// getRAConfig returns the current RA configuration for all interfaces
func getRAConfig(w http.ResponseWriter, r *http.Request) {
	store, err := loadRADVDConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load RA config: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.Interfaces)
}

// setRAConfig configures Router Advertisement for an interface
func setRAConfig(w http.ResponseWriter, r *http.Request) {
	var req RAConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate interface name
	if !isValidInterfaceName(req.Interface) {
		http.Error(w, "Invalid interface name", http.StatusBadRequest)
		return
	}

	// If enabled, validate prefix
	if req.Enabled && req.Prefix == "" {
		http.Error(w, "Prefix is required when enabling Router Advertisement", http.StatusBadRequest)
		return
	}

	// Load current config
	store, err := loadRADVDConfig()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load RA config: %v", err), http.StatusInternalServerError)
		return
	}

	// Update config for this interface
	store.Interfaces[req.Interface] = RADVDConfig{
		Interface:  req.Interface,
		Enabled:    req.Enabled,
		Prefix:     req.Prefix,
		DNSServers: req.DNSServers,
	}

	// Save config
	if err := saveRADVDConfig(store); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save RA config: %v", err), http.StatusInternalServerError)
		return
	}

	// Regenerate radvd.conf
	if err := generateRADVDConfig(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate radvd config: %v", err), http.StatusInternalServerError)
		return
	}

	// Check if any interface has RA enabled
	hasEnabledRA := false
	for _, cfg := range store.Interfaces {
		if cfg.Enabled {
			hasEnabledRA = true
			break
		}
	}

	// Manage radvd service based on enabled interfaces
	if hasEnabledRA {
		// Enable and start/reload radvd
		if err := enableRADVDService(); err != nil {
			fmt.Printf("Warning: Failed to enable radvd service: %v\n", err)
		}
		if err := reloadRADVD(); err != nil {
			// Try starting if reload fails
			if startErr := startRADVD(); startErr != nil {
				http.Error(w, fmt.Sprintf("Failed to start radvd: %v", startErr), http.StatusInternalServerError)
				return
			}
		}
		fmt.Printf("Router Advertisement %s for interface %s (prefix: %s)\n",
			map[bool]string{true: "enabled", false: "disabled"}[req.Enabled],
			req.Interface, req.Prefix)
	} else {
		// No enabled interfaces, stop radvd
		if err := stopRADVD(); err != nil {
			fmt.Printf("Warning: Failed to stop radvd: %v\n", err)
		}
		fmt.Println("Router Advertisement disabled on all interfaces, stopped radvd")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Router Advertisement configuration applied for %s", req.Interface),
	})
}

// getRAStatus returns the status of the radvd service
func getRAStatus(w http.ResponseWriter, r *http.Request) {
	isRunning, _ := getRADVDStatus()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running": isRunning,
	})
}
