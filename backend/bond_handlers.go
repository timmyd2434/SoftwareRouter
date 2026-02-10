package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// --- Bond Interface Types ---

type BondCreateRequest struct {
	Name    string   `json:"name"`    // e.g., "bond0"
	Members []string `json:"members"` // e.g., ["eth0", "eth1"]
	Mode    string   `json:"mode"`    // "802.3ad", "active-backup", "balance-rr", "balance-xor", "broadcast"
	MIIMon  int      `json:"miimon"`  // Link monitoring interval in milliseconds (default: 100)
}

type BondMemberRequest struct {
	BondName string `json:"bondName"` // e.g., "bond0"
	Member   string `json:"member"`   // e.g., "eth0"
}

type BondInfo struct {
	Name        string       `json:"name"`
	Members     []string     `json:"members"`
	Mode        string       `json:"mode"`
	MIIMon      int          `json:"miimon"`
	IPAddresses []string     `json:"ipAddresses"`
	MTU         int          `json:"mtu"`
	IsUp        bool         `json:"isUp"`
	MemberState []MemberInfo `json:"memberState"` // Per-member status
}

type MemberInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "up", "down", "active", "backup"
	Speed  string `json:"speed"`  // "1000 Mbps", "unknown"
}

// --- Bond Mode Mapping ---

// bondModeToNumber converts user-friendly mode names to kernel mode numbers
func bondModeToNumber(mode string) (string, error) {
	modes := map[string]string{
		"balance-rr":    "0",
		"active-backup": "1",
		"balance-xor":   "2",
		"broadcast":     "3",
		"802.3ad":       "4",
		"balance-tlb":   "5",
		"balance-alb":   "6",
	}

	if num, ok := modes[mode]; ok {
		return num, nil
	}

	// Also accept direct numbers (0-6)
	if mode >= "0" && mode <= "6" {
		return mode, nil
	}

	return "", fmt.Errorf("invalid bond mode: %s (valid: balance-rr, active-backup, balance-xor, broadcast, 802.3ad, balance-tlb, balance-alb)", mode)
}

// bondNumberToMode converts kernel mode number to user-friendly name
func bondNumberToMode(num string) string {
	modes := map[string]string{
		"0": "balance-rr",
		"1": "active-backup",
		"2": "balance-xor",
		"3": "broadcast",
		"4": "802.3ad",
		"5": "balance-tlb",
		"6": "balance-alb",
	}

	if name, ok := modes[num]; ok {
		return name
	}
	return num // Return as-is if unknown
}

// --- Helper Functions ---

// isBondInterface checks if an interface is a bond
func isBondInterface(name string) bool {
	// Check if /sys/class/net/<name>/bonding exists
	bondPath := filepath.Join("/sys/class/net", name, "bonding")
	if _, err := os.Stat(bondPath); err == nil {
		return true
	}
	return false
}

// getBondMembers returns the list of interfaces that are members of the bond
func getBondMembers(bondName string) ([]string, error) {
	// Bond slaves are listed in /sys/class/net/<bond>/bonding/slaves
	slavesPath := filepath.Join("/sys/class/net", bondName, "bonding", "slaves")

	data, err := os.ReadFile(slavesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // Bond exists but has no members
		}
		return nil, fmt.Errorf("failed to read bond members: %w", err)
	}

	slaves := strings.TrimSpace(string(data))
	if slaves == "" {
		return []string{}, nil
	}

	return strings.Fields(slaves), nil
}

// getBondMode returns the current bonding mode
func getBondMode(bondName string) (string, error) {
	modePath := filepath.Join("/sys/class/net", bondName, "bonding", "mode")
	data, err := os.ReadFile(modePath)
	if err != nil {
		return "", err
	}

	// Output format: "802.3ad 4" or "active-backup 1"
	mode := strings.TrimSpace(string(data))
	parts := strings.Fields(mode)
	if len(parts) >= 2 {
		return parts[0], nil // Return the name part
	}
	return mode, nil
}

// getBondMIIMon returns the MII monitoring interval
func getBondMIIMon(bondName string) (int, error) {
	miimonPath := filepath.Join("/sys/class/net", bondName, "bonding", "miimon")
	data, err := os.ReadFile(miimonPath)
	if err != nil {
		return 0, err
	}

	miimon, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return miimon, nil
}

// getMemberState returns detailed state for each bond member
func getMemberState(bondName string, members []string) []MemberInfo {
	memberStates := make([]MemberInfo, 0, len(members))

	for _, member := range members {
		state := MemberInfo{
			Name:   member,
			Status: "unknown",
			Speed:  "unknown",
		}

		// Check link status via /sys/class/net/<member>/operstate
		operstatePath := filepath.Join("/sys/class/net", member, "operstate")
		if data, err := os.ReadFile(operstatePath); err == nil {
			operstate := strings.TrimSpace(string(data))
			state.Status = operstate // "up" or "down"
		}

		// Check speed via /sys/class/net/<member>/speed
		speedPath := filepath.Join("/sys/class/net", member, "speed")
		if data, err := os.ReadFile(speedPath); err == nil {
			speed := strings.TrimSpace(string(data))
			if speed != "-1" && speed != "" {
				state.Speed = speed + " Mbps"
			}
		}

		memberStates = append(memberStates, state)
	}

	return memberStates
}

// validateBondMember checks if an interface can be added to a bond
func validateBondMember(ifaceName string) error {
	// Check if interface exists
	ifacePath := filepath.Join("/sys/class/net", ifaceName)
	if _, err := os.Stat(ifacePath); os.IsNotExist(err) {
		return fmt.Errorf("interface %s does not exist", ifaceName)
	}

	// Check if interface is already a bond
	if isBondInterface(ifaceName) {
		return fmt.Errorf("interface %s is a bond and cannot be added to another bond", ifaceName)
	}

	// Check if interface is already in a bond or bridge
	masterPath := filepath.Join("/sys/class/net", ifaceName, "master")
	if _, err := os.Stat(masterPath); err == nil {
		// Interface already has a master
		return fmt.Errorf("interface %s is already a member of a bond or bridge", ifaceName)
	}

	return nil
}

// isValidBondName validates bond naming convention (bond[0-9]+)
func isValidBondName(name string) bool {
	match, _ := regexp.MatchString(`^bond[0-9]+$`, name)
	return match
}

// ensureBondingModuleLoaded ensures the bonding kernel module is loaded
func ensureBondingModuleLoaded() error {
	// Check if bonding module is loaded
	if _, err := os.Stat("/sys/module/bonding"); err == nil {
		return nil // Already loaded
	}

	// Try to load the module
	fmt.Println("Loading bonding kernel module...")
	if output, err := runPrivilegedCombinedOutput("modprobe", "bonding"); err != nil {
		return fmt.Errorf("failed to load bonding module: %w, output: %s (ensure kernel supports bonding)", err, string(output))
	}

	return nil
}

// --- HTTP Handlers ---

func getBonds(w http.ResponseWriter, r *http.Request) {
	// Get all network interfaces
	netPath := "/sys/class/net"
	entries, err := os.ReadDir(netPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read network interfaces: %v", err), http.StatusInternalServerError)
		return
	}

	bonds := []BondInfo{}

	for _, entry := range entries {
		ifaceName := entry.Name()

		// Check if this is a bond
		if !isBondInterface(ifaceName) {
			continue
		}

		// Get bond members
		members, err := getBondMembers(ifaceName)
		if err != nil {
			fmt.Printf("Warning: Failed to get members for bond %s: %v\n", ifaceName, err)
			members = []string{}
		}

		// Get bond mode
		mode, err := getBondMode(ifaceName)
		if err != nil {
			fmt.Printf("Warning: Failed to get mode for bond %s: %v\n", ifaceName, err)
			mode = "unknown"
		}

		// Get MII monitoring interval
		miimon, err := getBondMIIMon(ifaceName)
		if err != nil {
			fmt.Printf("Warning: Failed to get miimon for bond %s: %v\n", ifaceName, err)
			miimon = 0
		}

		// Get interface details (reuse existing logic)
		iface, err := getInterfaceByName(ifaceName)
		if err != nil {
			fmt.Printf("Warning: Failed to get interface details for %s: %v\n", ifaceName, err)
			continue
		}

		// Get member states
		memberStates := getMemberState(ifaceName, members)

		bondInfo := BondInfo{
			Name:        ifaceName,
			Members:     members,
			Mode:        mode,
			MIIMon:      miimon,
			IPAddresses: iface.IPAddresses,
			MTU:         iface.MTU,
			IsUp:        iface.IsUp,
			MemberState: memberStates,
		}

		bonds = append(bonds, bondInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bonds)
}

func createBond(w http.ResponseWriter, r *http.Request) {
	var req BondCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate bond name
	if !isValidBondName(req.Name) {
		http.Error(w, "Invalid bond name. Must match pattern: bond[0-9]+ (e.g., bond0, bond1)", http.StatusBadRequest)
		return
	}

	// Check if bond already exists
	if isBondInterface(req.Name) {
		http.Error(w, fmt.Sprintf("Bond %s already exists", req.Name), http.StatusConflict)
		return
	}

	// Validate bond mode
	modeNum, err := bondModeToNumber(req.Mode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set default MIIMon if not provided
	if req.MIIMon == 0 {
		req.MIIMon = 100 // Default 100ms
	}

	// Validate MIIMon range (0-10000 ms)
	if req.MIIMon < 0 || req.MIIMon > 10000 {
		http.Error(w, "MIIMon must be between 0 and 10000 milliseconds", http.StatusBadRequest)
		return
	}

	// Validate all member interfaces before creating
	for _, member := range req.Members {
		if !isValidInterfaceName(member) {
			http.Error(w, fmt.Sprintf("Invalid interface name: %s", member), http.StatusBadRequest)
			return
		}

		if err := validateBondMember(member); err != nil {
			http.Error(w, fmt.Sprintf("Cannot add %s to bond: %v", member, err), http.StatusBadRequest)
			return
		}
	}

	// Ensure bonding module is loaded
	if err := ensureBondingModuleLoaded(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to load bonding module: %v", err), http.StatusInternalServerError)
		return
	}

	// Create the bond interface
	fmt.Printf("Creating bond: %s (mode: %s)\n", req.Name, req.Mode)
	if _, err := runPrivilegedCombinedOutput("ip", "link", "add", req.Name, "type", "bond", "mode", modeNum); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create bond: %v", err), http.StatusInternalServerError)
		return
	}

	// Set MII monitoring interval
	miimonPath := filepath.Join("/sys/class/net", req.Name, "bonding", "miimon")
	if err := os.WriteFile(miimonPath, []byte(fmt.Sprintf("%d", req.MIIMon)), 0644); err != nil {
		fmt.Printf("Warning: Failed to set miimon: %v\n", err)
		// Don't fail, continue with default
	}

	// For 802.3ad mode, set recommended LACP parameters
	if req.Mode == "802.3ad" || modeNum == "4" {
		// Set LACP rate to slow (default, more stable)
		lacpRatePath := filepath.Join("/sys/class/net", req.Name, "bonding", "lacp_rate")
		if err := os.WriteFile(lacpRatePath, []byte("slow"), 0644); err != nil {
			fmt.Printf("Warning: Failed to set LACP rate: %v\n", err)
		}

		// Set xmit hash policy for better load distribution
		xmitHashPath := filepath.Join("/sys/class/net", req.Name, "bonding", "xmit_hash_policy")
		if err := os.WriteFile(xmitHashPath, []byte("layer3+4"), 0644); err != nil {
			fmt.Printf("Warning: Failed to set xmit_hash_policy: %v\n", err)
		}
	}

	// Bring the bond interface up first (required before adding members in some modes)
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", req.Name, "up"); err != nil {
		fmt.Printf("Warning: Failed to bring up bond %s: %v\n", req.Name, err)
	}

	// Add member interfaces to the bond
	for _, member := range req.Members {
		fmt.Printf("Adding %s to bond %s\n", member, req.Name)

		// Bring member down first (recommended for bonding)
		runPrivilegedCombinedOutput("ip", "link", "set", member, "down")

		// Add to bond
		if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "master", req.Name); err != nil {
			// If adding member fails, try to clean up the bond
			fmt.Printf("ERROR: Failed to add %s to bond, cleaning up: %v\n", member, err)
			runPrivilegedCombinedOutput("ip", "link", "delete", req.Name)
			http.Error(w, fmt.Sprintf("Failed to add %s to bond: %v", member, err), http.StatusInternalServerError)
			return
		}

		// Bring member up
		if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "up"); err != nil {
			fmt.Printf("Warning: Failed to bring up member %s: %v\n", member, err)
		}
	}

	fmt.Printf("Bond %s created successfully with %d members (mode: %s, miimon: %dms)\n",
		req.Name, len(req.Members), req.Mode, req.MIIMon)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Bond %s created with %d member(s) in mode %s", req.Name, len(req.Members), req.Mode),
	})
}

func deleteBond(w http.ResponseWriter, r *http.Request) {
	bondName := r.URL.Query().Get("name")
	if bondName == "" {
		http.Error(w, "Missing bond name parameter", http.StatusBadRequest)
		return
	}

	// Validate it's actually a bond
	if !isBondInterface(bondName) {
		http.Error(w, fmt.Sprintf("%s is not a bond interface", bondName), http.StatusBadRequest)
		return
	}

	fmt.Printf("Deleting bond: %s\n", bondName)

	// Get members before deletion
	members, err := getBondMembers(bondName)
	if err != nil {
		fmt.Printf("Warning: Failed to get bond members: %v\n", err)
	}

	// Remove all members from bond first
	for _, member := range members {
		fmt.Printf("Removing %s from bond %s\n", member, bondName)
		if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "nomaster"); err != nil {
			fmt.Printf("Warning: Failed to remove %s from bond: %v\n", member, err)
		}
	}

	// Bring down the bond
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", bondName, "down"); err != nil {
		fmt.Printf("Warning: Failed to bring down bond: %v\n", err)
	}

	// Delete the bond interface
	if output, err := runPrivilegedCombinedOutput("ip", "link", "delete", bondName); err != nil {
		errMsg := fmt.Sprintf("Failed to delete bond: %v\nOutput: %s", err, string(output))
		fmt.Printf("ERROR: %s\n", errMsg)
		http.Error(w, errMsg, http.StatusInternalServerError)
		return
	}

	fmt.Printf("Bond %s deleted successfully\n", bondName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Bond %s deleted successfully", bondName),
	})
}

func addBondMember(w http.ResponseWriter, r *http.Request) {
	var req BondMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.BondName == "" || req.Member == "" {
		http.Error(w, "Bond name and member interface required", http.StatusBadRequest)
		return
	}

	// Validate bond exists
	if !isBondInterface(req.BondName) {
		http.Error(w, fmt.Sprintf("%s is not a bond interface", req.BondName), http.StatusBadRequest)
		return
	}

	// Validate member can be added
	if err := validateBondMember(req.Member); err != nil {
		http.Error(w, fmt.Sprintf("Cannot add %s to bond: %v", req.Member, err), http.StatusBadRequest)
		return
	}

	fmt.Printf("Adding %s to bond %s\n", req.Member, req.BondName)

	// Bring member down first
	runPrivilegedCombinedOutput("ip", "link", "set", req.Member, "down")

	// Add member to bond
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", req.Member, "master", req.BondName); err != nil {
		http.Error(w, fmt.Sprintf("Failed to add member to bond: %v", err), http.StatusInternalServerError)
		return
	}

	// Bring member up
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", req.Member, "up"); err != nil {
		fmt.Printf("Warning: Failed to bring up member %s: %v\n", req.Member, err)
	}

	fmt.Printf("Member %s added to bond %s successfully\n", req.Member, req.BondName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Added %s to bond %s", req.Member, req.BondName),
	})
}

func removeBondMember(w http.ResponseWriter, r *http.Request) {
	var req BondMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.BondName == "" || req.Member == "" {
		http.Error(w, "Bond name and member interface required", http.StatusBadRequest)
		return
	}

	// Validate bond exists
	if !isBondInterface(req.BondName) {
		http.Error(w, fmt.Sprintf("%s is not a bond interface", req.BondName), http.StatusBadRequest)
		return
	}

	// Get current members to verify the interface is actually a member
	members, err := getBondMembers(req.BondName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get bond members: %v", err), http.StatusInternalServerError)
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
		http.Error(w, fmt.Sprintf("%s is not a member of bond %s", req.Member, req.BondName), http.StatusBadRequest)
		return
	}

	fmt.Printf("Removing %s from bond %s\n", req.Member, req.BondName)

	// Remove member from bond
	if _, err := runPrivilegedCombinedOutput("ip", "link", "set", req.Member, "nomaster"); err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove member from bond: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Member %s removed from bond %s successfully\n", req.Member, req.BondName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Removed %s from bond %s", req.Member, req.BondName),
	})
}
