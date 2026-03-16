package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// --- Validation Functions ---

func isValidInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 16 {
		return false
	}
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func isValidIP(ip string) bool {
	// Simple check for CIDR or plain IP
	_, _, err := net.ParseCIDR(ip)
	if err == nil {
		return true
	}
	parsed := net.ParseIP(ip)
	return parsed != nil
}

// --- Metadata Storage ---

func loadInterfaceMetadata() (*InterfaceMetadataStore, error) {
	store := &InterfaceMetadataStore{
		Metadata: make(map[string]InterfaceMetadata),
	}

	data, err := os.ReadFile(metadataFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, return empty store
			return store, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}

	return store, nil
}

func saveInterfaceMetadata(store *InterfaceMetadataStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataFilePath, data, 0600)
}

// --- HTTP Handlers ---

func getInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save interface metadata", err)
		return
	}

	var result []InterfaceInfo
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		var ipv4List []string
		var ipv6List []string

		for _, addr := range addrs {
			ipStr := addr.String()
			// Parse to determine if IPv4 or IPv6
			ip, _, err := net.ParseCIDR(ipStr)
			if err != nil {
				// If not CIDR, try plain IP
				ip = net.ParseIP(ipStr)
			}

			if ip != nil {
				if ip.To4() != nil {
					// IPv4 address
					ipv4List = append(ipv4List, ipStr)
				} else {
					// IPv6 address
					ipv6List = append(ipv6List, ipStr)
				}
			}
		}

		isUp := (i.Flags & net.FlagUp) != 0

		result = append(result, InterfaceInfo{
			Index:         i.Index,
			Name:          i.Name,
			MAC:           i.HardwareAddr.String(),
			IPAddresses:   ipv4List,
			IPv6Addresses: ipv6List,
			MTU:           i.MTU,
			Flags:         i.Flags.String(),
			IsUp:          isUp,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func setInterfaceState(w http.ResponseWriter, r *http.Request) {
	var req InterfaceStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate state
	if req.State != "up" && req.State != "down" {
		http.Error(w, "State must be 'up' or 'down'", http.StatusBadRequest)
		return
	}

	fmt.Printf("Setting interface %s to %s\n", req.InterfaceName, req.State)

	if output, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", req.InterfaceName, req.State); err != nil {
		errMsg := fmt.Sprintf("Failed to set interface state: %s\nOutput: %s", err.Error(), string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		respondSystemError(w, ErrInterfaceConfigFailed, "Failed to update interface", fmt.Errorf("%s", errMsg))
		return
	}

	fmt.Printf("Interface %s set to %s successfully\n", req.InterfaceName, req.State)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Interface %s is now %s", req.InterfaceName, req.State),
	})
}

func getInterfaceMetadata(w http.ResponseWriter, r *http.Request) {
	store, err := loadInterfaceMetadata()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to load metadata", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.Metadata)
}

type SetInterfaceLabelRequest struct {
	InterfaceName string `json:"interfaceName"`
	Label         string `json:"label"`
	Description   string `json:"description"`
	Color         string `json:"color"`
}

func setInterfaceLabel(w http.ResponseWriter, r *http.Request) {
	var req SetInterfaceLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.InterfaceName == "" {
		http.Error(w, "Interface name is required", http.StatusBadRequest)
		return
	}

	// Validate label (optional but recommended values)
	validLabels := map[string]bool{
		"WAN": true, "LAN": true, "DMZ": true, "Guest": true,
		"Management": true, "Trunk": true, "": true, // Empty is allowed (to clear)
	}
	if req.Label != "" && !validLabels[req.Label] {
		fmt.Printf("Warning: Non-standard label '%s' used\n", req.Label)
	}

	store, err := loadInterfaceMetadata()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to load metadata", err)
		return
	}

	// Update or create metadata
	store.Metadata[req.InterfaceName] = InterfaceMetadata{
		InterfaceName: req.InterfaceName,
		Label:         req.Label,
		Description:   req.Description,
		Color:         req.Color,
	}

	if err := saveInterfaceMetadata(store); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save metadata", err)
		return
	}

	fmt.Printf("Interface %s labeled as %s\n", req.InterfaceName, req.Label)

	// Trigger firewall update to respect new zones
	go firewallManager.ApplyFirewallRules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Interface %s updated", req.InterfaceName),
	})
}

// --- VLAN Management ---

func createVLAN(w http.ResponseWriter, r *http.Request) {
	var req VLANCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs to prevent command injection
	if !isValidInterfaceName(req.ParentInterface) {
		http.Error(w, "Invalid parent interface name", http.StatusBadRequest)
		return
	}

	// Validate VLAN ID (1-4094)
	if req.VLANId < 1 || req.VLANId > 4094 {
		http.Error(w, "VLAN ID must be between 1 and 4094", http.StatusBadRequest)
		return
	}

	vlanInterface := fmt.Sprintf("%s.%d", req.ParentInterface, req.VLANId)
	fmt.Printf("Creating VLAN: %s\n", vlanInterface)

	// Create VLAN interface using ip link
	// Using absolute path for safety and explicit arguments
	if _, err := runPrivilegedCombinedOutput("/usr/sbin/ip", "link", "add", "link", req.ParentInterface, "name", vlanInterface, "type", "vlan", "id", fmt.Sprintf("%d", req.VLANId)); err != nil {
		http.Error(w, "Failed to create VLAN interface", http.StatusInternalServerError)
		return
	}

	// Bring the VLAN interface up
	if output, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", vlanInterface, "up"); err != nil {
		fmt.Printf("Warning: Failed to bring up VLAN interface: %s\n", string(output))
	}

	fmt.Printf("VLAN %s created successfully\n", vlanInterface)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"interface": vlanInterface,
		"message":   fmt.Sprintf("VLAN interface %s created successfully", vlanInterface),
	})
}

func deleteVLAN(w http.ResponseWriter, r *http.Request) {
	interfaceName := r.URL.Query().Get("interface")
	if interfaceName == "" {
		http.Error(w, "Missing interface parameter", http.StatusBadRequest)
		return
	}

	// Safety check: only allow deletion of VLAN interfaces (contain a dot)
	if !strings.Contains(interfaceName, ".") || !isValidInterfaceName(interfaceName) {
		http.Error(w, "Invalid VLAN interface name", http.StatusBadRequest)
		return
	}

	fmt.Printf("Deleting VLAN: %s\n", interfaceName)

	if output, err := runPrivilegedCombinedOutput("ip", "link", "delete", interfaceName); err != nil {
		errMsg := fmt.Sprintf("Failed to delete VLAN: %s\nOutput: %s", err.Error(), string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		respondSystemError(w, ErrInterfaceConfigFailed, "Failed to add IP address", fmt.Errorf("%s", errMsg))
		return
	}

	fmt.Printf("VLAN %s deleted successfully\n", interfaceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("VLAN interface %s deleted successfully", interfaceName),
	})
}

// --- IP Configuration ---

func configureIP(w http.ResponseWriter, r *http.Request) {
	var req IPConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate action
	if req.Action != "add" && req.Action != "del" {
		http.Error(w, "Action must be 'add' or 'del'", http.StatusBadRequest)
		return
	}

	if !isValidInterfaceName(req.InterfaceName) || !isValidIP(req.IPAddress) {
		http.Error(w, "Invalid interface name or IP address format", http.StatusBadRequest)
		return
	}

	// Check for IP address conflicts before applying
	if req.Action == "add" {
		if err := checkIPConflicts(req.IPAddress, req.InterfaceName, req.Action); err != nil {
			log.Printf("IP conflict detected: %v", err)
			respondNetworkError(w, ErrNetworkInvalidIP, "IP conflict detected", err)
			return
		}
	}

	fmt.Printf("Configuring IP: %s %s on %s\n", req.Action, req.IPAddress, req.InterfaceName)

	// Use ip addr add/del
	output, err := runPrivilegedCombinedOutput("ip", "addr", req.Action, req.IPAddress, "dev", req.InterfaceName)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to configure IP address: %v, output: %s", err, string(output))
		log.Printf("ERROR: %s", errMsg)
		respondSystemError(w, ErrInterfaceConfigFailed, "Failed to assign IP", fmt.Errorf("%s", errMsg))
		return
	}

	fmt.Printf("IP address %s %sed successfully on %s\n", req.IPAddress, req.Action, req.InterfaceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s %sed successfully on %s", req.IPAddress, req.Action, req.InterfaceName),
	})
}

// --- IPv6 Configuration ---

func configureIPv6(w http.ResponseWriter, r *http.Request) {
	var req IPConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate action
	if req.Action != "add" && req.Action != "del" {
		http.Error(w, "Action must be 'add' or 'del'", http.StatusBadRequest)
		return
	}

	if !isValidInterfaceName(req.InterfaceName) || !isValidIP(req.IPAddress) {
		http.Error(w, "Invalid interface name or IP address format", http.StatusBadRequest)
		return
	}

	// Validate that this is an IPv6 address
	ip, _, err := net.ParseCIDR(req.IPAddress)
	if err != nil {
		http.Error(w, "Invalid IPv6 CIDR format (e.g., 2001:db8::1/64)", http.StatusBadRequest)
		return
	}
	if ip.To4() != nil {
		http.Error(w, "This endpoint is for IPv6 addresses only. Use /api/configure-ip for IPv4", http.StatusBadRequest)
		return
	}

	// Check for IP address conflicts before applying
	if req.Action == "add" {
		if err := checkIPConflicts(req.IPAddress, req.InterfaceName, req.Action); err != nil {
			log.Printf("IPv6 conflict detected: %v", err)
			respondNetworkError(w, ErrNetworkInvalidIP, "IP conflict detected", err)
			return
		}
	}

	fmt.Printf("%sing IPv6 address %s on %s\n", req.Action, req.IPAddress, req.InterfaceName)

	// Use ip -6 addr add/del
	var cmd string
	if req.Action == "add" {
		cmd = "add"
	} else {
		cmd = "del"
	}

	if output, err := runPrivilegedCombinedOutput("ip", "-6", "addr", cmd, req.IPAddress, "dev", req.InterfaceName); err != nil {
		errMsg := fmt.Sprintf("Failed to %s IPv6 address: %s\nOutput: %s", req.Action, err.Error(), string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		respondSystemError(w, ErrInterfaceConfigFailed, "Failed to update IP", fmt.Errorf("%s", errMsg))
		return
	}

	fmt.Printf("IPv6 address %s %sed successfully on %s\n", req.IPAddress, req.Action, req.InterfaceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IPv6 %s %sed successfully on %s", req.IPAddress, req.Action, req.InterfaceName),
	})
}
