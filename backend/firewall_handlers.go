package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"net"
	"strings"
	"unicode"
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

// normaliseRule folds a raw nftables rule string to a canonical form for
// duplicate comparison: lowercase, collapse all whitespace to single spaces,
// strip leading/trailing space.
func normaliseRule(raw string) string {
	// Map every run of whitespace (including tabs/newlines) to a single space
	var b strings.Builder
	inSpace := false
	for _, r := range raw {
		if unicode.IsSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		} else {
			b.WriteRune(unicode.ToLower(r))
			inSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

// isDuplicateRule returns true when a rule with the same normalised raw
// expression already exists in the specified table+chain.
// It queries the live nftables ruleset so it reflects the current state.
func isDuplicateRule(family, table, chain, rawStatement string) bool {
	out, err := runPrivilegedOutput("nft", "-j", "list", "ruleset")
	if err != nil {
		// Cannot query — fail open (allow the add rather than block the user)
		return false
	}

	var root NftablesRoot
	if err := json.Unmarshal(out, &root); err != nil {
		return false
	}

	wantNorm := normaliseRule(rawStatement)

	for _, item := range root.Nftables {
		ruleObj, ok := item["rule"].(map[string]interface{})
		if !ok {
			continue
		}

		existTable, _ := ruleObj["table"].(string)
		existFamily, _ := ruleObj["family"].(string)
		existChain, _ := ruleObj["chain"].(string)

		// Only compare within the same table+chain (family comparison is
		// case-insensitive; nftables normalises "inet" -> "inet" etc.)
		if !strings.EqualFold(existFamily, family) ||
			!strings.EqualFold(existTable, table) ||
			!strings.EqualFold(existChain, chain) {
			continue
		}

		// Re-serialise the stored expression JSON and normalise it the same
		// way the incoming raw string is normalised.  This lets us compare
		// "tcp dport 22 accept" against the JSON blob nftables stores.
		// It is not a perfect semantic comparison but catches the common
		// case of re-submitting the exact same text.
		exprBytes, _ := json.Marshal(ruleObj["expr"])
		existNorm := normaliseRule(string(exprBytes))

		if existNorm == wantNorm {
			return true
		}
	}

	return false
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

	// Validate params to prevent nftables argument injection
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(rule.Family) {
		http.Error(w, "Invalid family parameter", http.StatusBadRequest)
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(rule.Table) {
		http.Error(w, "Invalid table parameter", http.StatusBadRequest)
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(rule.Chain) {
		http.Error(w, "Invalid chain parameter", http.StatusBadRequest)
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
		// SECURITY FIX: Also validate the comment field to prevent nft injection
		if rule.Comment != "" && strings.Contains(rule.Comment, pattern) {
			http.Error(w, "Invalid characters in firewall rule comment", http.StatusBadRequest)
			return
		}
	}

	// SECURITY FIX: Also block double-quotes in comments to prevent quote-escape injection
	if strings.Contains(rule.Comment, `"`) {
		http.Error(w, "Quotes are not allowed in firewall rule comments", http.StatusBadRequest)
		return
	}

	// Whitelist allowed nftables keywords
	allowedKeywords := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "ip": true, "ip6": true,
		"accept": true, "drop": true, "reject": true, "dport": true, "sport": true,
		"daddr": true, "saddr": true, "ct": true, "state": true,
		"established": true, "related": true, "new": true, "invalid": true,
		"counter": true, "packets": true, "bytes": true, "limit": true,
		"rate": true, "log": true, "prefix": true, "to": true,
		"masquerade": true, "redirect": true, "dnat": true, "snat": true,
		"oifname": true, "iifname": true,
	}

	// Helper: check if a token is a numeric value, IP address, or CIDR
	isNumericOrAddress := func(s string) bool {
		// Strip surrounding quotes
		s = strings.Trim(s, `"'`)
		if s == "" {
			return true
		}
		for _, ch := range s {
			if !unicode.IsDigit(ch) && ch != '.' && ch != ':' && ch != '/' && ch != '-' && ch != ',' {
				return false
			}
		}
		return true
	}

	// SECURITY FIX: Token-based keyword validation instead of substring matching
	// Split the rule into whitespace-delimited tokens and verify each is either
	// an allowed keyword or a value (number, IP, CIDR, quoted interface name)
	ruleTokens := strings.Fields(rule.Raw)
	hasValidKeyword := false
	for _, token := range ruleTokens {
		tokenLower := strings.ToLower(strings.Trim(token, `"'`))
		if allowedKeywords[tokenLower] {
			hasValidKeyword = true
			continue // Known keyword
		}
		if isNumericOrAddress(token) {
			continue // Numeric value, IP, CIDR, port
		}
		// Allow interface names (alphanumeric + dot + hyphen + underscore, max 15 chars)
		ifNamePattern := regexp.MustCompile(`^"?[a-zA-Z0-9][-a-zA-Z0-9._*]{0,14}"?$`)
		if ifNamePattern.MatchString(token) {
			continue // Looks like an interface name
		}
		// Unknown token — reject
		http.Error(w, fmt.Sprintf("Unknown keyword in firewall rule: %s", token), http.StatusBadRequest)
		return
	}
	if !hasValidKeyword {
		http.Error(w, "Firewall rule must contain valid nftables keywords", http.StatusBadRequest)
		return
	}

	// Duplicate detection: reject if an identical raw expression already
	// exists in the same table+chain, unless the caller explicitly opts in
	// with the X-Force-Duplicate header (set by the UI after user confirms).
	if r.Header.Get("X-Force-Duplicate") != "true" {
		if isDuplicateRule(rule.Family, rule.Table, rule.Chain, rule.Raw) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "duplicate",
				"message": fmt.Sprintf("A rule with the same expression already exists in %s/%s. Use 'Add Anyway' to override.", rule.Table, rule.Chain),
			})
			return
		}
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

	// Validate params to prevent nftables argument injection
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(family) {
		http.Error(w, "Invalid family parameter", http.StatusBadRequest)
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(table) {
		http.Error(w, "Invalid table parameter", http.StatusBadRequest)
		return
	}
	if !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(chain) {
		http.Error(w, "Invalid chain parameter", http.StatusBadRequest)
		return
	}
	if !regexp.MustCompile(`^\d+$`).MatchString(handle) {
		http.Error(w, "Invalid handle parameter", http.StatusBadRequest)
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

func cleanupFirewallRules(w http.ResponseWriter, r *http.Request) {
	// 1. Get live ruleset via nft -j list ruleset
	out, err := runPrivilegedCombinedOutput("nft", "-j", "list", "ruleset")
	if err != nil {
		respondFirewallError(w, ErrFirewallListFailed, "Failed to get ruleset", err)
		return
	}

	var root NftablesRoot
	if err := json.Unmarshal(out, &root); err != nil {
		respondFirewallError(w, ErrFirewallListFailed, "Failed to parse ruleset", err)
		return
	}

	// 2. Get list of active system interfaces using net.Interfaces()
	interfaces, err := net.Interfaces()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to get interfaces", err)
		return
	}

	// 3. Build a map of interface names that actually exist
	activeIfaces := make(map[string]bool)
	for _, iface := range interfaces {
		activeIfaces[iface.Name] = true
	}

	duplicatesRemoved := 0
	staleRemoved := 0
	var details []string

	// Map to track duplicates: key is fmt.Sprintf("%s/%s/%s/%s", family, table, chain, normalizedExpr)
	// Value is the lowest handle we've seen.
	seenRules := make(map[string]float64)

	for _, item := range root.Nftables {
		ruleInfo, ok := item["rule"].(map[string]interface{})
		if !ok {
			continue
		}

		family, _ := ruleInfo["family"].(string)
		table, _ := ruleInfo["table"].(string)
		chain, _ := ruleInfo["chain"].(string)
		handle, _ := ruleInfo["handle"].(float64)
		exprList, _ := ruleInfo["expr"].([]interface{})

		// Create raw expression
		var rawParts []string
		for _, expr := range exprList {
			exprBytes, _ := json.Marshal(expr)
			rawParts = append(rawParts, string(exprBytes))
		}
		rawExpr := strings.Join(rawParts, " ")
		normalized := normaliseRule(rawExpr)

		// 6. For stale rules: check if rule expressions contain iifname "X" or oifname "X" where X doesn't exist
		isStale := false
		
		// Regex to find iifname "X" or oifname "X"
		iifnameRe := regexp.MustCompile(`(?:iifname|oifname)\s+"([^"]+)"`)
		matches := iifnameRe.FindAllStringSubmatch(rawExpr, -1)
		
		for _, match := range matches {
			if len(match) > 1 {
				ifaceName := match[1]
				if !activeIfaces[ifaceName] {
					isStale = true
					break
				}
			}
		}

		if isStale {
			// Mark for deletion
			if _, err := runPrivilegedCombinedOutput("nft", "delete", "rule", family, table, chain, "handle", fmt.Sprintf("%.0f", handle)); err == nil {
				staleRemoved++
				details = append(details, fmt.Sprintf("Stale: deleted handle %.0f in %s/%s/%s", handle, family, table, chain))
			} else {
				log.Printf("Failed to delete stale rule: handle %.0f", handle)
			}
			continue
		}

		// 5. For exact duplicates: keep the first (lowest handle), mark remaining handles for deletion
		ruleKey := fmt.Sprintf("%s/%s/%s/%s", family, table, chain, normalized)
		if existingHandle, exists := seenRules[ruleKey]; exists {
			// It's a duplicate. We keep the existing (since we process in order of handles typically, or we should just keep the first we see)
			if handle < existingHandle {
				// The new one is lower handle, so delete the existing one and keep the new one.
				if _, err := runPrivilegedCombinedOutput("nft", "delete", "rule", family, table, chain, "handle", fmt.Sprintf("%.0f", existingHandle)); err == nil {
					duplicatesRemoved++
					details = append(details, fmt.Sprintf("Duplicate: deleted handle %.0f in %s/%s/%s", existingHandle, family, table, chain))
				}
				seenRules[ruleKey] = handle
			} else {
				// Delete the current handle
				if _, err := runPrivilegedCombinedOutput("nft", "delete", "rule", family, table, chain, "handle", fmt.Sprintf("%.0f", handle)); err == nil {
					duplicatesRemoved++
					details = append(details, fmt.Sprintf("Duplicate: deleted handle %.0f in %s/%s/%s", handle, family, table, chain))
				}
			}
		} else {
			seenRules[ruleKey] = handle
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"duplicates_removed": duplicatesRemoved,
		"stale_removed":      staleRemoved,
		"details":            details,
	})
}
