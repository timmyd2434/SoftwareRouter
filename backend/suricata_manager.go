package main

import (
	"encoding/json"
	"fmt"
	"log"
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

		if err := toggleIPSMode(req.Enabled); err != nil {
			respondSystemError(w, ErrSystemServiceControl, "Failed to toggle IPS mode", err)
			return
		}

		// Save configuration
		configLock.Lock()
		config.IPSEnabled = req.Enabled
		if err := saveConfigLocked(); err != nil {
			configLock.Unlock()
			respondSystemError(w, ErrSystemConfigSave, "Failed to save IPS config", err)
			return
		}
		configLock.Unlock()

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

// toggleIPSMode modifies the Suricata operating mode and nftables rules
func toggleIPSMode(enable bool) error {
	// 1. Modify /etc/default/suricata
	defaultFile := "/etc/default/suricata"
	data, err := os.ReadFile(defaultFile)
	if err == nil {
		content := string(data)
		if enable {
			content = strings.ReplaceAll(content, "LISTENMODE=af-packet", "LISTENMODE=nfq")
			// If neither exists, append it (fallback)
			if !strings.Contains(content, "LISTENMODE=nfq") {
				content += "\nLISTENMODE=nfq\n"
			}
		} else {
			content = strings.ReplaceAll(content, "LISTENMODE=nfq", "LISTENMODE=af-packet")
			if !strings.Contains(content, "LISTENMODE=af-packet") {
				content += "\nLISTENMODE=af-packet\n"
			}
		}
		// Write back
		if err := os.WriteFile(defaultFile, []byte(content), 0644); err != nil {
			log.Printf("Warning: Could not write /etc/default/suricata: %v", err)
		}
	} else {
		log.Printf("Warning: /etc/default/suricata not found, skipping LISTENMODE edit")
	}

	// 2. Add or Remove NFTables queue rule
	// nft add rule inet filter forward queue num 0 bypass
	// nft delete rule inet filter forward handle X
	if enable {
		// First check if rule already exists to avoid duplicates
		out, err := runPrivilegedCombinedOutput("nft", "list", "chain", "inet", "filter", "forward")
		if err == nil && !strings.Contains(string(out), "queue num 0") {
			if _, err := runPrivilegedCombinedOutput("nft", "add", "rule", "inet", "filter", "forward", "queue", "num", "0", "bypass"); err != nil {
				return fmt.Errorf("failed to add nftables queue rule: %v", err)
			}
		}
	} else {
		// Remove queue rule
		// Easiest way to remove a specific rule without knowing handle is to rebuild the chain or find the handle.
		// For simplicity, we can fetch the handle using json output, or flush and recreate forward chain.
		// Since forward chain might have other rules (like from VPN), we must find the handle.
		out, err := runPrivilegedOutput("nft", "-j", "list", "chain", "inet", "filter", "forward")
		if err == nil {
			var root NftablesRoot
			if err := json.Unmarshal(out, &root); err == nil {
				for _, item := range root.Nftables {
					if ruleObj, ok := item["rule"].(map[string]interface{}); ok {
						rawJsonBytes, _ := json.Marshal(ruleObj["expr"])
						rawJson := string(rawJsonBytes)
						if strings.Contains(rawJson, "queue") {
							if handle, ok := ruleObj["handle"].(float64); ok {
								runPrivilegedCombinedOutput("nft", "delete", "rule", "inet", "filter", "forward", "handle", fmt.Sprintf("%d", int(handle)))
							}
						}
					}
				}
			}
		}
	}

	// 3. Restart Suricata service
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
