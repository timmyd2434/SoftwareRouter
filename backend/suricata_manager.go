package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// IPSToggleRequest represents a request to enable or disable IPS mode
type IPSToggleRequest struct {
	Enabled bool `json:"enabled"`
}

// AppControlRequest represents a request to update blocked application categories
type AppControlRequest struct {
	Categories []string `json:"categories"`
}

// CategoryToRuleMap maps user-friendly categories to Emerging Threats rule patterns
var CategoryToRuleMap = map[string]string{
	"P2P":          "ET POLICY.*BitTorrent|ET POLICY.*Peer-to-Peer",
	"Malware":      "ET MALWARE",
	"Social Media": "ET INFO.*Facebook|ET INFO.*Twitter|ET INFO.*Instagram|ET INFO.*TikTok",
	"Adult":        "ET POLICY.*Porn",
	"Gaming":       "ET INFO.*Steam|ET INFO.*Xbox|ET INFO.*Playstation",
}

// handleSuricataIPS handles GET/POST for the IPS toggle
func handleSuricataIPS(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configLock.RLock()
		enabled := config.IPSEnabled
		configLock.RUnlock()
		writeJSON(w, map[string]bool{"enabled": enabled})
		return
	}

	if r.Method == http.MethodPost {
		var req IPSToggleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Save configuration first (to make sure it's reflected in the global config during ApplyFirewallRules)
		configLock.Lock()
		oldEnabled := config.IPSEnabled
		config.IPSEnabled = req.Enabled
		if err := saveConfigLocked(); err != nil {
			config.IPSEnabled = oldEnabled // Rollback in-memory
			configLock.Unlock()
			respondSystemError(w, ErrSystemConfigSave, "Failed to save IPS config", err)
			return
		}
		configLock.Unlock()

		if err := toggleIPSMode(req.Enabled); err != nil {
			// Rollback configuration on failure
			configLock.Lock()
			config.IPSEnabled = oldEnabled
			_ = saveConfigLocked()
			configLock.Unlock()
			respondSystemError(w, ErrSystemServiceControl, "Failed to toggle IPS mode", err)
			return
		}

		auditJSON, _ := json.Marshal(map[string]bool{"enabled": req.Enabled})
		logAuditEvent(getUsernameFromToken(r), "suricata.ips_toggle", "global", string(auditJSON), getClientIP(r), true)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleSuricataAppControl handles GET/POST for the App Control categories
func handleSuricataAppControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configLock.RLock()
		categories := config.BlockedAppCategories
		if categories == nil {
			categories = []string{}
		}
		configLock.RUnlock()
		writeJSON(w, map[string][]string{"categories": categories})
		return
	}

	if r.Method == http.MethodPost {
		var req AppControlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Validate: cap number of categories to prevent abuse
		if len(req.Categories) > len(CategoryToRuleMap) {
			http.Error(w, "Too many categories", http.StatusBadRequest)
			return
		}
		// Validate: only allow known category names
		for _, cat := range req.Categories {
			if _, known := CategoryToRuleMap[cat]; !known {
				http.Error(w, "Unknown category: "+cat, http.StatusBadRequest)
				return
			}
		}

		if err := updateAppControlRules(req.Categories); err != nil {
			respondSystemError(w, ErrSystemServiceControl, "Failed to update App Control rules", err)
			return
		}

		// Save configuration
		configLock.Lock()
		config.BlockedAppCategories = req.Categories
		if err := saveConfigLocked(); err != nil {
			configLock.Unlock()
			respondSystemError(w, ErrSystemConfigSave, "Failed to save App Control config", err)
			return
		}
		configLock.Unlock()

		auditJSON, _ := json.Marshal(map[string][]string{"categories": req.Categories})
		logAuditEvent(getUsernameFromToken(r), "suricata.app_control", "global", string(auditJSON), getClientIP(r), true)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// toggleIPSMode modifies the Suricata operating mode and systemd / firewall rules
func toggleIPSMode(enable bool) error {
	overrideDir := "/etc/systemd/system/suricata.service.d"
	overrideFile := overrideDir + "/override.conf"

	if enable {
		// 1. Create drop-in override for IPS (NFQ mode)
		if err := os.MkdirAll(overrideDir, 0755); err != nil {
			return fmt.Errorf("failed to create systemd override directory: %v", err)
		}
		overrideContent := `[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
`
		if err := os.WriteFile(overrideFile, []byte(overrideContent), 0644); err != nil {
			return fmt.Errorf("failed to write systemd override file: %v", err)
		}
	} else {
		// 2. Remove drop-in override to revert to default IDS (AF_PACKET mode)
		if err := os.Remove(overrideFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove systemd override file: %v", err)
		}
	}

	// 3. Reload systemd manager configuration
	if _, err := runPrivilegedCombinedOutput("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %v", err)
	}

	// 4. Re-apply firewall rules (which will configure the forward queue rule if enabled)
	if err := firewallManager.ApplyFirewallRules(false); err != nil {
		return fmt.Errorf("failed to apply firewall rules for IPS mode: %v", err)
	}

	// 5. Restart Suricata service to apply the mode change
	if _, err := runPrivilegedCombinedOutput("systemctl", "restart", "suricata"); err != nil {
		return fmt.Errorf("failed to restart suricata: %v", err)
	}

	return nil
}

// updateAppControlRules modifies modify.conf and reloads Suricata rules.
// It uses --no-merge to skip downloading new rules from the internet,
// only re-applying the existing local ruleset with the updated modify.conf.
func updateAppControlRules(categories []string) error {
	modifyConfPath := "/etc/suricata/modify.conf"

	var rules []string
	for _, cat := range categories {
		if pattern, exists := CategoryToRuleMap[cat]; exists {
			// Write rule to convert alerts to drops for this pattern
			rules = append(rules, fmt.Sprintf("re: \"%s\" => drop", pattern))
		}
	}

	// Create the directory if it doesn't exist
	os.MkdirAll("/etc/suricata", 0755)

	content := strings.Join(rules, "\n")
	if err := os.WriteFile(modifyConfPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write modify.conf: %v", err)
	}

	// Use --no-merge to skip downloading new rules from the internet.
	// This only re-processes the existing local ruleset with the updated modify.conf,
	// making this operation fast (seconds) rather than a full internet update (minutes).
	if _, err := runPrivilegedCombinedOutput("suricata-update", "--no-merge"); err != nil {
		return fmt.Errorf("failed to run suricata-update: %v", err)
	}

	// Reload suricata rules live without a full restart
	if _, err := runPrivilegedCombinedOutput("systemctl", "reload", "suricata"); err != nil {
		// Fallback to restart if live reload fails (e.g., older Suricata version)
		if _, restartErr := runPrivilegedCombinedOutput("systemctl", "restart", "suricata"); restartErr != nil {
			return fmt.Errorf("failed to reload suricata after rule update: %v", restartErr)
		}
	}

	return nil
}
