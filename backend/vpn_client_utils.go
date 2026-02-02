package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// VPNClientStatus represents the state of the OpenVPN client connection
type VPNClientStatus struct {
	Connected   bool   `json:"connected"`
	IPAddress   string `json:"ip_address"`
	Uptime      string `json:"uptime"`
	ServiceName string `json:"service_name"`
}

// VPNPolicy represents a routing rule for Split Tunneling
type VPNPolicy struct {
	SourceIP    string `json:"source_ip"`
	Description string `json:"description"`
}

const (
	vpnClientConfigDir = "/etc/openvpn/client"
	vpnAuthFile        = "/etc/openvpn/client/pia.auth"
	vpnConfigFile      = "/etc/openvpn/client/pia.conf"
	vpnSystemdService  = "openvpn-client@pia"
	vpnPoliciesFile    = "/etc/softrouter/vpn_policies.json"
)

// loadVPNPolicies reads the persistent list of policies from disk
func loadVPNPolicies() ([]VPNPolicy, error) {
	var policies []VPNPolicy
	data, err := os.ReadFile(vpnPoliciesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []VPNPolicy{}, nil
		}
		return nil, err
	}
	err = json.Unmarshal(data, &policies)
	return policies, err
}

// saveVPNPolicies writes the list of policies to disk
func saveVPNPolicies(policies []VPNPolicy) error {
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(vpnPoliciesFile, data, 0644)
}

// getVPNClientStatus checks systemd and interface status
func getVPNClientStatus(w http.ResponseWriter, r *http.Request) {
	status := VPNClientStatus{ServiceName: vpnSystemdService}

	// Check systemd status
	output, _ := runPrivilegedOutput("systemctl", "is-active", vpnSystemdService)
	isActive := strings.TrimSpace(string(output)) == "active"

	status.Connected = isActive

	if isActive {
		// Get uptime
		outUptime, _ := runPrivilegedOutput("systemctl", "show", vpnSystemdService, "--property=ActiveEnterTimestamp")
		status.Uptime = strings.TrimPrefix(strings.TrimSpace(string(outUptime)), "ActiveEnterTimestamp=")

		// Get IP from tun1 (assuming we force tun1) or trying to find the tun interface
		// A robust way creates a specific device name, but let's try to find the one associated with the PID or just 'tun1'
		outIP, err := runPrivilegedOutput("ip", "-4", "addr", "show", "tun1")
		if err == nil {
			lines := strings.Split(string(outIP), "\n")
			for _, line := range lines {
				if strings.Contains(line, "inet") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						status.IPAddress = parts[1]
						break
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// uploadVPNClientConfig handles .ovpn file upload and credentials
func uploadVPNClientConfig(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20) // 10MB limit
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	file, _, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "Config file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 1. Ensure directories exist
	os.MkdirAll(vpnClientConfigDir, 0755)

	// 2. Save Auth File
	authContent := fmt.Sprintf("%s\n%s", username, password)
	if err := os.WriteFile(vpnAuthFile, []byte(authContent), 0600); err != nil {
		http.Error(w, "Failed to save credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Process Config File
	// We read the uploaded file, inject our specific settings, and write to disk
	var configLines []string
	// (Simplification: read entire file to memory)
	buf := make([]byte, 1024*1024)
	n, _ := file.Read(buf)
	content := string(buf[:n])

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		// remove existing auth-user-pass or dev lines to avoid conflict
		if strings.HasPrefix(strings.TrimSpace(line), "auth-user-pass") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "dev ") {
			continue
		}
		configLines = append(configLines, line)
	}

	// Inject our mandatory settings
	configLines = append(configLines, "")
	configLines = append(configLines, "# SoftRouter Injected Settings")
	configLines = append(configLines, fmt.Sprintf("auth-user-pass %s", vpnAuthFile))
	configLines = append(configLines, "dev tun1")          // Force tun1 for easy routing
	configLines = append(configLines, "route-noexec")      // Manual routing handling
	configLines = append(configLines, "script-security 2") // Allow scripts if needed (future proofing)

	finalConfig := strings.Join(configLines, "\n")
	if err := os.WriteFile(vpnConfigFile, []byte(finalConfig), 0644); err != nil {
		http.Error(w, "Failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Enable service execution
	runPrivileged("systemctl", "daemon-reload")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Configuration saved successfully. You can now connect."})
}

// controlVPNClient starts/stops the service
func controlVPNClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // "start" or "stop"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var output []byte
	var err error
	if req.Action == "start" {
		output, err = runPrivilegedCombinedOutput("systemctl", "restart", vpnSystemdService)
	} else {
		output, err = runPrivilegedCombinedOutput("systemctl", "stop", vpnSystemdService)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Action failed: %s\nOutput: %s", err.Error(), string(output)), http.StatusInternalServerError)
		return
	}

	// If starting, give it a moment and then apply routing policies
	if req.Action == "start" {
		go func() {
			time.Sleep(3 * time.Second)
			refreshVPNRouting()
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// getVPNPolicies returns the list of policies
func getVPNPolicies(w http.ResponseWriter, r *http.Request) {
	policies, _ := loadVPNPolicies()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

// addVPNPolicy adds a new source IP to route through VPN
func addVPNPolicy(w http.ResponseWriter, r *http.Request) {
	var req VPNPolicy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policies, _ := loadVPNPolicies()
	// Check duplicate
	for _, p := range policies {
		if p.SourceIP == req.SourceIP {
			http.Error(w, "Policy for this IP already exists", http.StatusConflict)
			return
		}
	}
	policies = append(policies, req)
	saveVPNPolicies(policies)
	refreshVPNRouting()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

// deleteVPNPolicy removes a policy
func deleteVPNPolicy(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	policies, _ := loadVPNPolicies()
	var newPolicies []VPNPolicy
	for _, p := range policies {
		if p.SourceIP != ip {
			newPolicies = append(newPolicies, p)
		}
	}
	saveVPNPolicies(newPolicies)
	refreshVPNRouting()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newPolicies)
}

// refreshVPNRouting applies ip rules based on current policies
func refreshVPNRouting() {
	// 1. Ensure Table 100 uses VPN interface
	// Check if tun1 is up
	if err := runPrivileged("ip", "link", "show", "tun1"); err != nil {
		// Tun1 down, no routing possible
		return
	}

	// Add default route to table 100
	// "ip route replace default dev tun1 table 100"
	runPrivileged("ip", "route", "replace", "default", "dev", "tun1", "table", "100")

	// 2. Flush existing rules for table 100 to avoid duplicates?
	// It's hard to selectively flush only ours without tagging.
	// For now, we will delete known policies and re-add.
	// Or we can list all rules and delete ones looking up table 100.
	// "ip rule del lookup 100" loops until error
	for {
		if err := runPrivileged("ip", "rule", "del", "lookup", "100"); err != nil {
			break
		}
	}

	// 3. Add rules for each policy
	policies, _ := loadVPNPolicies()
	for _, p := range policies {
		runPrivileged("ip", "rule", "add", "from", p.SourceIP, "lookup", "100")
	}

	// Ensure cache flush
	runPrivileged("ip", "route", "flush", "cache")
}
