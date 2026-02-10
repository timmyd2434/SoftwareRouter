package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// handleFirewallAliases handles CRUD operations for firewall aliases
func handleFirewallAliases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getFirewallAliases(w, r)
	case http.MethodPost:
		createFirewallAlias(w, r)
	case http.MethodPut:
		updateFirewallAlias(w, r)
	case http.MethodDelete:
		deleteFirewallAlias(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getFirewallAliases returns all aliases
func getFirewallAliases(w http.ResponseWriter, r *http.Request) {
	store, err := loadFirewallAliases()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load aliases: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.Aliases)
}

// createFirewallAlias creates a new alias
func createFirewallAlias(w http.ResponseWriter, r *http.Request) {
	var newAlias FirewallAlias
	if err := json.NewDecoder(r.Body).Decode(&newAlias); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate alias
	if err := validateAlias(newAlias); err != nil {
		http.Error(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// Load existing aliases
	store, err := loadFirewallAliases()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load aliases: %v", err), http.StatusInternalServerError)
		return
	}

	// Check for duplicate name
	for _, alias := range store.Aliases {
		if strings.EqualFold(alias.Name, newAlias.Name) {
			http.Error(w, fmt.Sprintf("Alias with name '%s' already exists", newAlias.Name), http.StatusConflict)
			return
		}
	}

	// Add new alias
	store.Aliases = append(store.Aliases, newAlias)

	// Save to disk
	if err := saveFirewallAliases(store); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save aliases: %v", err), http.StatusInternalServerError)
		return
	}

	// Regenerate firewall rules to include new alias
	if err := firewallManager.ApplyFirewallRules(); err != nil {
		fmt.Printf("Warning: Failed to apply firewall rules after alias creation: %v\n", err)
		// Don't fail the request - alias is saved, firewall will be updated on next apply
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Alias created"})
}

// updateFirewallAlias updates an existing alias
func updateFirewallAlias(w http.ResponseWriter, r *http.Request) {
	var updatedAlias FirewallAlias
	if err := json.NewDecoder(r.Body).Decode(&updatedAlias); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate alias
	if err := validateAlias(updatedAlias); err != nil {
		http.Error(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
		return
	}

	// Load existing aliases
	store, err := loadFirewallAliases()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load aliases: %v", err), http.StatusInternalServerError)
		return
	}

	// Find and update the alias
	found := false
	for i, alias := range store.Aliases {
		if strings.EqualFold(alias.Name, updatedAlias.Name) {
			store.Aliases[i] = updatedAlias
			found = true
			break
		}
	}

	if !found {
		http.Error(w, fmt.Sprintf("Alias '%s' not found", updatedAlias.Name), http.StatusNotFound)
		return
	}

	// Save to disk
	if err := saveFirewallAliases(store); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save aliases: %v", err), http.StatusInternalServerError)
		return
	}

	// Regenerate firewall rules
	if err := firewallManager.ApplyFirewallRules(); err != nil {
		fmt.Printf("Warning: Failed to apply firewall rules after alias update: %v\n", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Alias updated"})
}

// deleteFirewallAlias deletes an alias
func deleteFirewallAlias(w http.ResponseWriter, r *http.Request) {
	// Get alias name from query parameter
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Alias name is required", http.StatusBadRequest)
		return
	}

	// Load existing aliases
	store, err := loadFirewallAliases()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load aliases: %v", err), http.StatusInternalServerError)
		return
	}

	// Find and remove the alias
	found := false
	newAliases := []FirewallAlias{}
	for _, alias := range store.Aliases {
		if strings.EqualFold(alias.Name, name) {
			found = true
			continue // Skip this alias (delete it)
		}
		newAliases = append(newAliases, alias)
	}

	if !found {
		http.Error(w, fmt.Sprintf("Alias '%s' not found", name), http.StatusNotFound)
		return
	}

	store.Aliases = newAliases

	// Save to disk
	if err := saveFirewallAliases(store); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save aliases: %v", err), http.StatusInternalServerError)
		return
	}

	// Regenerate firewall rules
	if err := firewallManager.ApplyFirewallRules(); err != nil {
		fmt.Printf("Warning: Failed to apply firewall rules after alias deletion: %v\n", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Alias deleted"})
}
