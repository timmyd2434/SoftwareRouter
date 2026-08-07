package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/google/uuid"
)

func validatePortForwardingRuleFields(rule PortForwardingRule) error {
	// 1. Port range validation
	if rule.ExternalPort < 1 || rule.ExternalPort > 65535 || rule.InternalPort < 1 || rule.InternalPort > 65535 {
		return fmt.Errorf("invalid ports")
	}

	// 2. IP Validation
	if rule.InternalIP == "" {
		return fmt.Errorf("internal IP required")
	}
	ip := net.ParseIP(rule.InternalIP)
	if ip == nil {
		return fmt.Errorf("invalid internal IP address format")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("internal IP cannot be loopback, unspecified, multicast, or link-local address")
	}

	// Verify IP is on LAN subnet
	configLock.RLock()
	subnetStr := config.ProtectedSubnet
	configLock.RUnlock()
	if subnetStr != "" {
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err == nil && !subnet.Contains(ip) {
			return fmt.Errorf("internal IP must be on the LAN subnet (%s)", subnetStr)
		}
	}

	// 3. Description Validation (strict whitelist to prevent injection)
	if len(rule.Description) > 100 {
		return fmt.Errorf("description too long (max 100 characters)")
	}
	for _, char := range rule.Description {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == ' ' || char == '_' || char == '-') {
			return fmt.Errorf("description contains invalid characters (only alphanumeric, spaces, underscores, and hyphens allowed)")
		}
	}

	// 4. Protocol validation
	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "" {
		return fmt.Errorf("invalid protocol (must be tcp or udp)")
	}

	return nil
}

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

	if err := validatePortForwardingRuleFields(rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	if err := validatePortForwardingRuleFields(rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := updatePortForwardingRule(id, rule); err != nil {
		respondSystemError(w, ErrNetworkRuleAddFailed, "Failed to update rule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}
