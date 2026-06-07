package main

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func listPortForwardingRules(w http.ResponseWriter, r *http.Request) {
	pfStoreLock.RLock()
	defer pfStoreLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pfStore.Rules)
}

func createPortForwardingRule(w http.ResponseWriter, r *http.Request) {
	var rule PortForwardingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Basic Validation
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 || rule.InternalPort < 1 || rule.InternalPort > 65535 {
		http.Error(w, "Invalid ports", http.StatusBadRequest)
		return
	}
	if rule.InternalIP == "" {
		http.Error(w, "Internal IP required", http.StatusBadRequest)
		return
	}

	rule.ID = uuid.New().String()
	rule.Enabled = true // Default to enabled

	if err := addPortForwardingRule(rule); err != nil {
		respondSystemError(w, ErrNetworkRuleAddFailed, "Failed to save rule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

func removePortForwardingRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	if err := deletePortForwardingRule(id); err != nil {
		respondSystemError(w, ErrNetworkRuleDeleteFailed, "Failed to delete rule", err)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func updatePortForwardingRuleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	var rule PortForwardingRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Basic Validation
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 || rule.InternalPort < 1 || rule.InternalPort > 65535 {
		http.Error(w, "Invalid ports", http.StatusBadRequest)
		return
	}
	if rule.InternalIP == "" {
		http.Error(w, "Internal IP required", http.StatusBadRequest)
		return
	}

	if err := updatePortForwardingRule(id, rule); err != nil {
		respondSystemError(w, ErrNetworkRuleAddFailed, "Failed to update rule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}
