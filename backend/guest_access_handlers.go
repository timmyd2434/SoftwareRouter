package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/google/uuid"
)

// guestInterfaceNames lists the interfaces currently labelled Guest/IoT/Isolated.
func guestInterfaceNames() []string {
	names := []string{}
	meta, err := loadInterfaceMetadata()
	if err != nil || meta == nil {
		return names
	}
	for iface, m := range meta.Metadata {
		if isGuestLabel(m.Label) && interfaceExists(iface) {
			names = append(names, iface)
		}
	}
	sort.Strings(names)
	return names
}

// GET /api/guest-access
func listGuestAccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules":            GetGuestAllowRules(),
		"settings":         GetGuestSettings(),
		"guest_interfaces": guestInterfaceNames(),
	})
}

func decodeGuestRule(w http.ResponseWriter, r *http.Request) (GuestAllowRule, bool) {
	var rule GuestAllowRule
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return rule, false
	}
	norm, err := normalizeGuestAllowRule(rule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return rule, false
	}
	norm.ID = rule.ID
	norm.Enabled = rule.Enabled
	return norm, true
}

// applyGuestRules saves the new list, regenerates the firewall, and restores the
// previous list if the firewall refuses it, so a bad change never sticks.
func applyGuestRules(w http.ResponseWriter, r *http.Request, action, resource string, updated []GuestAllowRule, errCode string) bool {
	previous := GetGuestAllowRules()
	details, _ := json.Marshal(updated)

	if err := setGuestAllowRules(updated); err != nil {
		logAuditEvent(getUsernameFromToken(r), action, resource, string(details), getClientIP(r), false)
		respondSystemError(w, errCode, "Failed to save guest access rules", err)
		return false
	}
	// Skip the rollback watchdog, as other direct UI updates do (port forwarding).
	if err := firewallManager.ApplyFirewallRules(true); err != nil {
		_ = setGuestAllowRules(previous)
		_ = firewallManager.ApplyFirewallRules(true)
		logAuditEvent(getUsernameFromToken(r), action, resource, string(details), getClientIP(r), false)
		respondSystemError(w, errCode, "Firewall rejected the change; it was not applied", err)
		return false
	}
	logAuditEvent(getUsernameFromToken(r), action, resource, string(details), getClientIP(r), true)
	return true
}

// POST /api/guest-access
func createGuestAccessRule(w http.ResponseWriter, r *http.Request) {
	rule, ok := decodeGuestRule(w, r)
	if !ok {
		return
	}
	existing := GetGuestAllowRules()
	if len(existing) >= maxGuestAllowRules {
		http.Error(w, fmt.Sprintf("Too many rules (max %d)", maxGuestAllowRules), http.StatusBadRequest)
		return
	}
	rule.ID = uuid.New().String()
	rule.Enabled = true
	if !applyGuestRules(w, r, "guest_access.add", rule.Name, append(existing, rule), ErrNetworkRuleAddFailed) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

// PUT /api/guest-access?id=...
func updateGuestAccessRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}
	rule, ok := decodeGuestRule(w, r)
	if !ok {
		return
	}
	rule.ID = id
	existing := GetGuestAllowRules()
	found := false
	for i := range existing {
		if existing[i].ID == id {
			existing[i] = rule
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	if !applyGuestRules(w, r, "guest_access.update", rule.Name, existing, ErrNetworkRuleAddFailed) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

// DELETE /api/guest-access?id=...
func deleteGuestAccessRule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}
	existing := GetGuestAllowRules()
	kept := make([]GuestAllowRule, 0, len(existing))
	name := ""
	for _, rule := range existing {
		if rule.ID == id {
			name = rule.Name
			continue
		}
		kept = append(kept, rule)
	}
	if len(kept) == len(existing) {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	if !applyGuestRules(w, r, "guest_access.delete", name, kept, ErrNetworkRuleDeleteFailed) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// PUT /api/guest-access/settings
func updateGuestSettings(w http.ResponseWriter, r *http.Request) {
	var settings GuestSettings
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&settings); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	previous := GetGuestSettings()
	details, _ := json.Marshal(settings)
	if err := setGuestSettings(settings); err != nil {
		logAuditEvent(getUsernameFromToken(r), "guest_access.settings", "dns", string(details), getClientIP(r), false)
		respondSystemError(w, ErrNetworkRuleAddFailed, "Failed to save guest network settings", err)
		return
	}
	// Same safety net as the rules: if the firewall refuses the change, put the old settings back.
	if err := firewallManager.ApplyFirewallRules(true); err != nil {
		_ = setGuestSettings(previous)
		_ = firewallManager.ApplyFirewallRules(true)
		logAuditEvent(getUsernameFromToken(r), "guest_access.settings", "dns", string(details), getClientIP(r), false)
		respondSystemError(w, ErrNetworkRuleAddFailed, "Firewall rejected the change; it was not applied", err)
		return
	}
	logAuditEvent(getUsernameFromToken(r), "guest_access.settings", "dns", string(details), getClientIP(r), true)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}
