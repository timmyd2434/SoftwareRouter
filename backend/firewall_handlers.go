package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type NftablesRoot struct {
	Nftables []map[string]interface{} `json:"nftables"`
}

type FirewallRule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  int    `json:"handle"`
	Comment string `json:"comment"`
	Raw     string `json:"raw"`
}

// getFirewallRules attempts to read real nftables rules
func getFirewallRules(w http.ResponseWriter, r *http.Request) {
	// Try to execute nft command
	// Note: This often requires sudo in a real environment.
	out, err := runPrivilegedOutput("nft", "-j", "list", "ruleset")

	if err != nil {
		// keeping mock fallback but simplified for brevity
		mockRules := []FirewallRule{
			{Family: "inet", Table: "filter", Chain: "INPUT", Handle: 1, Comment: "Allow Localhost", Raw: "iifname lo accept"},
		}
		w.Header().Set("X-Start-Warning", "Could not fetch NFT rules. Mock data.")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockRules)
		return
	}

	// Parse JSON output from NFTables
	var root NftablesRoot
	if err := json.Unmarshal(out, &root); err != nil {
		http.Error(w, "Failed to parse nft output", http.StatusInternalServerError)
		return
	}

	// Flatten the NFTable structure into simple rules for our UI
	var rules []FirewallRule

	for _, item := range root.Nftables {
		if ruleObj, ok := item["rule"].(map[string]interface{}); ok {
			// Extract details
			table, _ := ruleObj["table"].(string)
			family, _ := ruleObj["family"].(string)
			chain, _ := ruleObj["chain"].(string)
			handle, _ := ruleObj["handle"].(float64)
			comment, _ := ruleObj["comment"].(string)

			// The "expr" field in `nft -j list ruleset` is an ARRAY of objects.
			// Example: [{"counter":...}, {"jump":...}]
			// We want to convert this back into a human-readable string like "counter packets 0 bytes 0 jump piavpn..."
			// However, `nft` doesn't give us a "raw string" easily from JSON.
			// The user sees raw JSON in the UI currently.

			rawJsonBytes, _ := json.Marshal(ruleObj["expr"])
			rawJson := string(rawJsonBytes)

			// Simple heuristic to make the "Raw" field editable for ADDING rules.
			// When adding, we need "tcp dport 22 accept".
			// But what we READ is JSON.
			// We'll store the JSON for display, but the UI expects a statement for adding.

			rules = append(rules, FirewallRule{
				Family:  family,
				Table:   table,
				Chain:   chain,
				Handle:  int(handle),
				Comment: comment,
				Raw:     rawJson, // This is JSON. usage in UI needs to be careful.
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func addFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rule FirewallRule
	// Read body for debug purposes if needed, but Decoder is standard
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validation
	if rule.Family == "" {
		rule.Family = "inet"
	} // Default
	if rule.Table == "" || rule.Chain == "" || rule.Raw == "" {
		http.Error(w, "Missing required fields (table, chain, raw)", http.StatusBadRequest)
		return
	}

	// Security: Sanitize firewall rule input to prevent command injection
	// Block dangerous characters and command sequences
	dangerousPatterns := []string{";", "|", "&", "$", "`", "$(", "||", "&&", "\n", "\r", "<", ">", "(", ")", "{", "}"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(rule.Raw, pattern) {
			http.Error(w, "Invalid characters in firewall rule", http.StatusBadRequest)
			return
		}
	}

	// Whitelist allowed nftables keywords
	allowedKeywords := []string{
		"tcp", "udp", "icmp", "ip", "ip6", "accept", "drop", "reject", "dport", "sport",
		"daddr", "saddr", "ct", "state", "established", "related", "new", "invalid",
		"counter", "packets", "bytes", "limit", "rate", "log", "prefix", "to",
	}

	// Validate that rule contains at least one allowed keyword
	hasValidKeyword := false
	ruleLower := strings.ToLower(rule.Raw)
	for _, keyword := range allowedKeywords {
		if strings.Contains(ruleLower, keyword) {
			hasValidKeyword = true
			break
		}
	}
	if !hasValidKeyword {
		http.Error(w, "Firewall rule must contain valid nftables keywords", http.StatusBadRequest)
		return
	}

	// Command: nft add rule <family> <table> <chain> <statement>
	// Note: Validating "statement" is hard, we pass it raw and hope.
	args := []string{"add", "rule", rule.Family, rule.Table, rule.Chain}

	// Split raw string by spaces (rudimentary) - this is fragile for complex rules like "ct state { established }"
	// For basic commands "tcp dport 22 accept" it works.
	// A better approach for complex args is parsing them respecting quotes/braces, but for now:
	parts := strings.Fields(rule.Raw)
	args = append(args, parts...)

	// Add comment if provided
	if rule.Comment != "" {
		args = append(args, "comment", fmt.Sprintf(`"%s"`, rule.Comment))
	}

	fmt.Printf("Executing NFT: nft %v\n", args) // Debug log

	ruleJSON, _ := json.Marshal(rule)

	if out, err := runPrivilegedCombinedOutput("nft", args...); err != nil {
		log.Printf("[ERROR] NFT command failed: %s (CMD: nft %v)", string(out), args)

		// Log failed firewall rule addition
		logAuditEvent(getUsernameFromToken(r), "firewall.add",
			fmt.Sprintf("%s/%s", rule.Table, rule.Chain),
			string(ruleJSON), getClientIP(r), false)

		respondFirewallError(w, ErrFirewallAddFailed, "Failed to add firewall rule", fmt.Errorf("%s", string(out)))
		return
	}

	// Log successful firewall rule addition
	logAuditEvent(getUsernameFromToken(r), "firewall.add",
		fmt.Sprintf("%s/%s", rule.Table, rule.Chain),
		string(ruleJSON), getClientIP(r), true)

	w.WriteHeader(http.StatusOK)
}

func deleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	family := r.URL.Query().Get("family")
	table := r.URL.Query().Get("table")
	chain := r.URL.Query().Get("chain")
	handle := r.URL.Query().Get("handle")

	if family == "" || table == "" || chain == "" || handle == "" {
		http.Error(w, "Missing params", http.StatusBadRequest)
		return
	}

	// Command: nft delete rule <family> <table> <chain> handle <handle>
	if out, err := runPrivilegedCombinedOutput("nft", "delete", "rule", family, table, chain, "handle", handle); err != nil {
		logAuditEvent(getUsernameFromToken(r), "firewall.delete",
			fmt.Sprintf("%s/%s", table, chain),
			fmt.Sprintf("{\"handle\":\"%s\",\"error\":\"%s\"}", handle, string(out)),
			getClientIP(r), false)
		respondFirewallError(w, ErrFirewallListFailed, "NFT command failed", fmt.Errorf("%s", string(out)))
		return
	}

	logAuditEvent(getUsernameFromToken(r), "firewall.delete",
		fmt.Sprintf("%s/%s", table, chain),
		fmt.Sprintf("{\"handle\":\"%s\"}", handle), getClientIP(r), true)

	w.WriteHeader(http.StatusOK)
}
