package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

// --- Bridge Interface Types ---

type BridgeCreateRequest struct {
	Name    string   `json:"name"`    // e.g., "br0"
	Members []string `json:"members"` // e.g., ["eth1", "eth2"]
}

type BridgeMemberRequest struct {
	BridgeName string `json:"bridgeName"` // e.g., "br0"
	Member     string `json:"member"`     // e.g., "eth1"
}

type BridgeInfo struct {
	Name        string   `json:"name"`
	Members     []string `json:"members"`
	IPAddresses []string `json:"ipAddresses"`
	MTU         int      `json:"mtu"`
	IsUp        bool     `json:"isUp"`
}

// --- Helper Functions ---

// isBridgeInterface checks if an interface is a bridge
func isBridgeInterface(name string) bool {
	// Check if /sys/class/net/<name>/bridge exists
	bridgePath := filepath.Join("/sys/class/net", name, "bridge")
	if _, err := os.Stat(bridgePath); err == nil {
		return true
	}
	return false
}

// getBridgeMembers returns the list of interfaces that are members of the bridge
func getBridgeMembers(bridgeName string) ([]string, error) {
	// Bridge members are listed in /sys/class/net/<bridge>/brif/
	brIfPath := filepath.Join("/sys/class/net", bridgeName, "brif")

	entries, err := os.ReadDir(brIfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // Bridge exists but has no members
		}
		return nil, fmt.Errorf("failed to read bridge members: %w", err)
	}

	members := make([]string, 0, len(entries))
	for _, entry := range entries {
		members = append(members, entry.Name())
	}

	return members, nil
}

// validateBridgeMember checks if an interface can be added to a bridge
func validateBridgeMember(ifaceName string) error {
	// Check if interface exists
	ifacePath := filepath.Join("/sys/class/net", ifaceName)
	if _, err := os.Stat(ifacePath); os.IsNotExist(err) {
		return fmt.Errorf("interface %s does not exist", ifaceName)
	}

	// Check if interface is already a bridge
	if isBridgeInterface(ifaceName) {
		return fmt.Errorf("interface %s is a bridge and cannot be added to another bridge", ifaceName)
	}

	// Check if interface is already in a bridge
	masterPath := filepath.Join("/sys/class/net", ifaceName, "master")
	if _, err := os.Stat(masterPath); err == nil {
		// Interface already has a master (is in a bridge)
		return fmt.Errorf("interface %s is already a member of a bridge", ifaceName)
	}

	return nil
}

// isValidBridgeName validates bridge naming convention (br[0-9]+)
func isValidBridgeName(name string) bool {
	match, _ := regexp.MatchString(`^br[0-9]+$`, name)
	return match
}

// --- HTTP Handlers ---

func getBridges(w http.ResponseWriter, r *http.Request) {
	// Get all network interfaces
	netPath := "/sys/class/net"
	entries, err := os.ReadDir(netPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read network interfaces: %v", err), http.StatusInternalServerError)
		return
	}

	bridges := []BridgeInfo{}

	for _, entry := range entries {
		ifaceName := entry.Name()

		// Check if this is a bridge
		if !isBridgeInterface(ifaceName) {
			continue
		}

		// Get bridge members
		members, err := getBridgeMembers(ifaceName)
		if err != nil {
			fmt.Printf("Warning: Failed to get members for bridge %s: %v\n", ifaceName, err)
			members = []string{}
		}

		// Get interface details (reuse existing logic)
		iface, err := getInterfaceByName(ifaceName)
		if err != nil {
			fmt.Printf("Warning: Failed to get interface details for %s: %v\n", ifaceName, err)
			continue
		}

		bridgeInfo := BridgeInfo{
			Name:        ifaceName,
			Members:     members,
			IPAddresses: iface.IPAddresses,
			MTU:         iface.MTU,
			IsUp:        iface.IsUp,
		}

		bridges = append(bridges, bridgeInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bridges)
}

func createBridge(w http.ResponseWriter, r *http.Request) {
	var req BridgeCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate bridge name
	if !isValidBridgeName(req.Name) {
		http.Error(w, "Invalid bridge name. Must match pattern: br[0-9]+ (e.g., br0, br1)", http.StatusBadRequest)
		return
	}

	// Check if bridge already exists
	if isBridgeInterface(req.Name) {
		http.Error(w, fmt.Sprintf("Bridge %s already exists", req.Name), http.StatusConflict)
		return
	}

	// Validate all member interfaces before creating
	for _, member := range req.Members {
		if !isValidInterfaceName(member) {
			http.Error(w, fmt.Sprintf("Invalid interface name: %s", member), http.StatusBadRequest)
			return
		}

		if err := validateBridgeMember(member); err != nil {
			http.Error(w, fmt.Sprintf("Cannot add %s to bridge: %v", member, err), http.StatusBadRequest)
			return
		}
	}

	// Create the bridge interface
	fmt.Printf("Creating bridge: %s\n", req.Name)
	if _, err := runPrivilegedCombinedOutput("ip", "link", "add", "name", req.Name, "type", "bridge"); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create bridge: %v", err), http.StatusInternalServerError)
		return
	}

	// Add member interfaces to the bridge
	for _, member := range req.Members {
		fmt.Printf("Adding %s to bridge %s\n", member, req.Name)
		if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "master", req.Name); err != nil {
			// If adding member fails, try to clean up the bridge
			fmt.Printf("ERROR: Failed to add %s to bridge, cleaning up: %v\n", member, err)
			runPrivilegedCombinedOutput("ip", "link", "delete", req.Name)
			http.Error(w, fmt.Sprintf("Failed to add %s to bridge: %v", member, err), http.StatusInternalServerError)
			return
		}
	}

	// Bring up the bridge interface
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", req.Name, "up"); err != nil {
		fmt.Printf("Warning: Failed to bring up bridge %s: %v\n", req.Name, err)
		// Don't fail the operation, bridge is created
	}

	fmt.Printf("Bridge %s created successfully with %d members\n", req.Name, len(req.Members))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Bridge %s created with %d member(s)", req.Name, len(req.Members)),
	})
}

func deleteBridge(w http.ResponseWriter, r *http.Request) {
	bridgeName := r.URL.Query().Get("name")
	if bridgeName == "" {
		http.Error(w, "Missing bridge name parameter", http.StatusBadRequest)
		return
	}

	// Validate it's actually a bridge
	if !isBridgeInterface(bridgeName) {
		http.Error(w, fmt.Sprintf("%s is not a bridge interface", bridgeName), http.StatusBadRequest)
		return
	}

	fmt.Printf("Deleting bridge: %s\n", bridgeName)

	// Get members before deletion
	members, err := getBridgeMembers(bridgeName)
	if err != nil {
		fmt.Printf("Warning: Failed to get bridge members: %v\n", err)
	}

	// Remove all members from bridge first (recommended but not strictly required)
	for _, member := range members {
		fmt.Printf("Removing %s from bridge %s\n", member, bridgeName)
		if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "nomaster"); err != nil {
			fmt.Printf("Warning: Failed to remove %s from bridge: %v\n", member, err)
		}
	}

	// Bring down the bridge
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", bridgeName, "down"); err != nil {
		fmt.Printf("Warning: Failed to bring down bridge: %v\n", err)
	}

	// Delete the bridge interface
	if output, err := runPrivilegedCombinedOutput("ip", "link", "delete", bridgeName); err != nil {
		errMsg := fmt.Sprintf("Failed to delete bridge: %v\nOutput: %s", err, string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	fmt.Printf("Bridge %s deleted successfully\n", bridgeName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Bridge %s deleted successfully", bridgeName),
	})
}

func addBridgeMember(w http.ResponseWriter, r *http.Request) {
	var req BridgeMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.BridgeName == "" || req.Member == "" {
		http.Error(w, "Bridge name and member interface required", http.StatusBadRequest)
		return
	}

	// Validate bridge exists
	if !isBridgeInterface(req.BridgeName) {
		http.Error(w, fmt.Sprintf("%s is not a bridge interface", req.BridgeName), http.StatusBadRequest)
		return
	}

	// Validate member can be added
	if err := validateBridgeMember(req.Member); err != nil {
		http.Error(w, fmt.Sprintf("Cannot add %s to bridge: %v", req.Member, err), http.StatusBadRequest)
		return
	}

	fmt.Printf("Adding %s to bridge %s\n", req.Member, req.BridgeName)

	// Add member to bridge
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", req.Member, "master", req.BridgeName); err != nil {
		http.Error(w, fmt.Sprintf("Failed to add member to bridge: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Member %s added to bridge %s successfully\n", req.Member, req.BridgeName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Added %s to bridge %s", req.Member, req.BridgeName),
	})
}

func removeBridgeMember(w http.ResponseWriter, r *http.Request) {
	var req BridgeMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.BridgeName == "" || req.Member == "" {
		http.Error(w, "Bridge name and member interface required", http.StatusBadRequest)
		return
	}

	// Validate bridge exists
	if !isBridgeInterface(req.BridgeName) {
		http.Error(w, fmt.Sprintf("%s is not a bridge interface", req.BridgeName), http.StatusBadRequest)
		return
	}

	// Get current members to verify the interface is actually a member
	members, err := getBridgeMembers(req.BridgeName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get bridge members: %v", err), http.StatusInternalServerError)
		return
	}

	found := false
	for _, member := range members {
		if member == req.Member {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, fmt.Sprintf("%s is not a member of bridge %s", req.Member, req.BridgeName), http.StatusBadRequest)
		return
	}

	fmt.Printf("Removing %s from bridge %s\n", req.Member, req.BridgeName)

	// Remove member from bridge
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", req.Member, "nomaster"); err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove member from bridge: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Member %s removed from bridge %s successfully\n", req.Member, req.BridgeName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Removed %s from bridge %s", req.Member, req.BridgeName),
	})
}

// getInterfaceByName is a helper to get interface details for a single interface
// This can be extracted from the existing getInterfaces() logic
func getInterfaceByName(name string) (*InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	addrs, _ := iface.Addrs()
	var ipList []string
	for _, addr := range addrs {
		ipList = append(ipList, addr.String())
	}

	isUp := (iface.Flags & net.FlagUp) != 0

	return &InterfaceInfo{
		Index:       iface.Index,
		Name:        iface.Name,
		MAC:         iface.HardwareAddr.String(),
		IPAddresses: ipList,
		MTU:         iface.MTU,
		Flags:       iface.Flags.String(),
		IsUp:        isUp,
	}, nil
}
