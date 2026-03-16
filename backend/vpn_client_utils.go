package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// validateVPNPolicy checks that a VPN split-tunneling policy is safe.
// It ensures the source IP is a single host address and not a broad subnet
// that would route entire network segments (including LAN traffic to the router)
// through the VPN tunnel.
func validateVPNPolicy(sourceIP string) error {
	if sourceIP == "" {
		return fmt.Errorf("source IP is required")
	}

	// Check if this is a CIDR notation
	if strings.Contains(sourceIP, "/") {
		ip, ipNet, err := net.ParseCIDR(sourceIP)
		if err != nil {
			return fmt.Errorf("invalid IP/CIDR format: %s", sourceIP)
		}

		// Only allow /32 (single host) for IPv4 or /128 for IPv6
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && ones < 32 {
			return fmt.Errorf("VPN policy source must be a single host IP address, not a subnet (%s) — "+
				"routing an entire subnet through the VPN would break local LAN access to the router. "+
				"Use a /32 host address like %s/32 instead", sourceIP, ip.String())
		}
		if bits == 128 && ones < 128 {
			return fmt.Errorf("VPN policy source must be a single host IPv6 address, not a subnet (%s) — "+
				"use a /128 host address instead", sourceIP)
		}
	} else {
		// Plain IP address (no CIDR) — validate it's a valid IP
		if net.ParseIP(sourceIP) == nil {
			return fmt.Errorf("invalid IP address format: %s", sourceIP)
		}
	}

	// Check if this is the router's own IP on any interface — routing the
	// router's own traffic through VPN would sever management access
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: could not enumerate interfaces for VPN policy validation: %v", err)
		return nil
	}

	policyIP := net.ParseIP(strings.Split(sourceIP, "/")[0])
	if policyIP == nil {
		return nil
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ifIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ifIP.Equal(policyIP) {
				return fmt.Errorf("cannot route the router's own IP (%s on %s) through the VPN — "+
					"this would sever management access to the router", sourceIP, iface.Name)
			}
		}
	}

	return nil
}

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
	return os.WriteFile(vpnPoliciesFile, data, 0600)
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
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // Limit total request size to 10MB
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
	defer file.Close() //nolint:errcheck

	// 1. Ensure directories exist
	os.MkdirAll(vpnClientConfigDir, 0750)

	// 2. Save Auth File
	// #nosec G304 G703: path is validated or constructed from safe internal sources
	authContent := fmt.Sprintf("%s\n%s", username, password)
	if err := os.WriteFile(vpnAuthFile, []byte(authContent), 0600); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save credentials", err)
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
	if err := os.WriteFile(vpnConfigFile, []byte(finalConfig), 0600); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to write config", err)
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
		respondInvalidRequest(w, "Invalid request")
		return
	}

	// SECURITY: Strictly validate action to prevent unexpected systemctl arguments
	if req.Action != "start" && req.Action != "stop" {
		http.Error(w, "Invalid action: must be 'start' or 'stop'", http.StatusBadRequest)
		return
	}

	var err error
	if req.Action == "start" {
		_, err = runPrivilegedCombinedOutput("systemctl", "restart", vpnSystemdService)
	} else {
		_, err = runPrivilegedCombinedOutput("systemctl", "stop", vpnSystemdService)
	}

	if err != nil {
		respondSystemError(w, ErrVPNControlFailed, "VPN action failed", err)
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
		respondInvalidRequest(w, "Invalid request")
		return
	}

	// Validate that the policy is safe (single host, not the router's own IP)
	if err := validateVPNPolicy(req.SourceIP); err != nil {
		respondInvalidRequest(w, "VPN policy validation failed")
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
