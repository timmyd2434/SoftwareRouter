package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const interfacesConfigPath = "/etc/softrouter/interfaces_config.json"

type SavedVLAN struct {
	ParentInterface string `json:"parentInterface"`
	VLANId          int    `json:"vlanId"`
}

type SavedBridge struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	STP     bool     `json:"stp"`
}

type SavedBond struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
	Mode    string   `json:"mode"`
	MIIMon  int      `json:"miimon"`
}

type SavedIP struct {
	InterfaceName string `json:"interfaceName"`
	IPAddress     string `json:"ipAddress"` // e.g., "192.168.1.1/24"
}

type InterfacesConfigStore struct {
	VLANs   map[string]SavedVLAN   `json:"vlans"`
	Bridges map[string]SavedBridge `json:"bridges"`
	Bonds   map[string]SavedBond   `json:"bonds"`
	IPs     []SavedIP              `json:"ips"`
}

var (
	interfacesStore     InterfacesConfigStore
	interfacesStoreLock sync.RWMutex
)

func init() {
	interfacesStore = InterfacesConfigStore{
		VLANs:   make(map[string]SavedVLAN),
		Bridges: make(map[string]SavedBridge),
		Bonds:   make(map[string]SavedBond),
		IPs:     []SavedIP{},
	}
}

// loadInterfacesConfig reads custom interfaces configuration from disk
func loadInterfacesConfig() error {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	data, err := os.ReadFile(interfacesConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Initialize with empty defaults if file doesn't exist
			interfacesStore = InterfacesConfigStore{
				VLANs:   make(map[string]SavedVLAN),
				Bridges: make(map[string]SavedBridge),
				Bonds:   make(map[string]SavedBond),
				IPs:     []SavedIP{},
			}
			return nil
		}
		return err
	}

	var store InterfacesConfigStore
	if err := json.Unmarshal(data, &store); err != nil {
		return err
	}

	if store.VLANs == nil {
		store.VLANs = make(map[string]SavedVLAN)
	}
	if store.Bridges == nil {
		store.Bridges = make(map[string]SavedBridge)
	}
	if store.Bonds == nil {
		store.Bonds = make(map[string]SavedBond)
	}
	if store.IPs == nil {
		store.IPs = []SavedIP{}
	}

	interfacesStore = store
	return nil
}

// saveInterfacesConfigLocked writes custom interfaces configuration to disk
func saveInterfacesConfigLocked() error {
	data, err := json.MarshalIndent(interfacesStore, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(interfacesConfigPath), 0750); err != nil {
		return err
	}

	return os.WriteFile(interfacesConfigPath, data, 0600)
}

// --- VLAN helpers ---

func persistVLAN(name string, vlan SavedVLAN) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	interfacesStore.VLANs[name] = vlan
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save VLAN persistence: %v", err)
	}
}

func removePersistedVLAN(name string) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	delete(interfacesStore.VLANs, name)
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save VLAN persistence: %v", err)
	}
}

// --- Bridge helpers ---

func persistBridge(name string, bridge SavedBridge) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	interfacesStore.Bridges[name] = bridge
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save Bridge persistence: %v", err)
	}
}

func removePersistedBridge(name string) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	delete(interfacesStore.Bridges, name)
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save Bridge persistence: %v", err)
	}
}

func updatePersistedBridgeMembers(name string, members []string) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	if br, ok := interfacesStore.Bridges[name]; ok {
		br.Members = members
		interfacesStore.Bridges[name] = br
		if err := saveInterfacesConfigLocked(); err != nil {
			log.Printf("ERROR: Failed to save Bridge members persistence: %v", err)
		}
	}
}

// --- Bond helpers ---

func persistBond(name string, bond SavedBond) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	interfacesStore.Bonds[name] = bond
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save Bond persistence: %v", err)
	}
}

func removePersistedBond(name string) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	delete(interfacesStore.Bonds, name)
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save Bond persistence: %v", err)
	}
}

func updatePersistedBondMembers(name string, members []string) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	if bo, ok := interfacesStore.Bonds[name]; ok {
		bo.Members = members
		interfacesStore.Bonds[name] = bo
		if err := saveInterfacesConfigLocked(); err != nil {
			log.Printf("ERROR: Failed to save Bond members persistence: %v", err)
		}
	}
}

// --- IP helpers ---

func persistIP(savedIP SavedIP) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	// Check if already saved
	for _, ip := range interfacesStore.IPs {
		if ip.InterfaceName == savedIP.InterfaceName && ip.IPAddress == savedIP.IPAddress {
			return
		}
	}

	interfacesStore.IPs = append(interfacesStore.IPs, savedIP)
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save IP persistence: %v", err)
	}
}

func removePersistedIP(savedIP SavedIP) {
	interfacesStoreLock.Lock()
	defer interfacesStoreLock.Unlock()

	newList := []SavedIP{}
	for _, ip := range interfacesStore.IPs {
		if ip.InterfaceName == savedIP.InterfaceName && ip.IPAddress == savedIP.IPAddress {
			continue
		}
		newList = append(newList, ip)
	}

	interfacesStore.IPs = newList
	if err := saveInterfacesConfigLocked(); err != nil {
		log.Printf("ERROR: Failed to save IP persistence: %v", err)
	}
}

// applyInterfacesConfig recreates saved custom interfaces and applies IP addresses
func applyInterfacesConfig() {
	if err := loadInterfacesConfig(); err != nil {
		log.Printf("ERROR: Failed to load interfaces config on boot: %v", err)
		return
	}

	interfacesStoreLock.RLock()
	store := interfacesStore
	interfacesStoreLock.RUnlock()

	log.Println("[PERSIST] Restoring custom network interfaces...")

	// 1. Recreate Bonds
	for name, bond := range store.Bonds {
		log.Printf("[PERSIST] Recreating Bond interface %s...", name)
		if isBondInterface(name) {
			log.Printf("[PERSIST] Bond %s already exists, skipping creation", name)
			continue
		}

		modeNum, err := bondModeToNumber(bond.Mode)
		if err != nil {
			log.Printf("ERROR: Invalid saved bond mode '%s' for %s: %v", bond.Mode, name, err)
			continue
		}

		if err := ensureBondingModuleLoaded(); err != nil {
			log.Printf("ERROR: Bonding module failed to load: %v", err)
			continue
		}

		// Create bond
		if _, err := runPrivilegedCombinedOutput("ip", "link", "add", name, "type", "bond", "mode", modeNum); err != nil {
			log.Printf("ERROR: Failed to create bond %s: %v", name, err)
			continue
		}

		// Set MII monitoring
		miimonVal := bond.MIIMon
		if miimonVal == 0 {
			miimonVal = 100
		}
		miimonPath := filepath.Join("/sys/class/net", name, "bonding", "miimon")
		_ = os.WriteFile(miimonPath, []byte(fmt.Sprintf("%d", miimonVal)), 0600)

		// Set LACP recommended policies
		if bond.Mode == "802.3ad" || modeNum == "4" {
			lacpRatePath := filepath.Join("/sys/class/net", name, "bonding", "lacp_rate")
			_ = os.WriteFile(lacpRatePath, []byte("slow"), 0600)
			xmitHashPath := filepath.Join("/sys/class/net", name, "bonding", "xmit_hash_policy")
			_ = os.WriteFile(xmitHashPath, []byte("layer3+4"), 0600)
		}

		// Bring bond UP
		_, _ = runPrivilegedCombinedOutput("ip", "link", "set", "dev", name, "up")

		// Add member interfaces
		for _, member := range bond.Members {
			log.Printf("[PERSIST] Adding member %s to bond %s...", member, name)
			_, _ = runPrivilegedCombinedOutput("ip", "link", "set", member, "down")
			if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "master", name); err != nil {
				log.Printf("ERROR: Failed to add member %s to bond %s: %v", member, name, err)
			}
			_, _ = runPrivilegedCombinedOutput("ip", "link", "set", member, "up")
		}
	}

	// 2. Recreate VLANs
	for name, vlan := range store.VLANs {
		log.Printf("[PERSIST] Recreating VLAN interface %s...", name)
		// Check if it already exists
		vlanPath := filepath.Join("/sys/class/net", name)
		if _, err := os.Stat(vlanPath); err == nil {
			log.Printf("[PERSIST] VLAN %s already exists, skipping creation", name)
			continue
		}

		// Create VLAN interface
		if _, err := runPrivilegedCombinedOutput("ip", "link", "add", "link", vlan.ParentInterface, "name", name, "type", "vlan", "id", fmt.Sprintf("%d", vlan.VLANId)); err != nil {
			log.Printf("ERROR: Failed to create VLAN %s: %v", name, err)
			continue
		}

		// Bring interface up
		_, _ = runPrivilegedCombinedOutput("ip", "link", "set", "dev", name, "up")
	}

	// 3. Recreate Bridges
	for name, bridge := range store.Bridges {
		log.Printf("[PERSIST] Recreating Bridge interface %s...", name)
		if isBridgeInterface(name) {
			log.Printf("[PERSIST] Bridge %s already exists, skipping creation", name)
			continue
		}

		// Create Bridge interface
		if _, err := runPrivilegedCombinedOutput("ip", "link", "add", "name", name, "type", "bridge"); err != nil {
			log.Printf("ERROR: Failed to create bridge %s: %v", name, err)
			continue
		}

		// Add members
		for _, member := range bridge.Members {
			log.Printf("[PERSIST] Adding member %s to bridge %s...", member, name)
			if _, err := runPrivilegedCombinedOutput("ip", "link", "set", member, "master", name); err != nil {
				log.Printf("ERROR: Failed to add member %s to bridge %s: %v", member, name, err)
			}
		}

		// Bring UP bridge
		_, _ = runPrivilegedCombinedOutput("ip", "link", "set", "dev", name, "up")

		// Set STP state
		_ = setSTPState(name, bridge.STP)
	}

	// 4. Reapply statically configured IP addresses
	for _, ip := range store.IPs {
		log.Printf("[PERSIST] Reapplying IP address %s to interface %s...", ip.IPAddress, ip.InterfaceName)
		// Try to add the IP address
		if _, err := runPrivilegedCombinedOutput("ip", "addr", "add", ip.IPAddress, "dev", ip.InterfaceName); err != nil {
			// This might fail if the IP is already configured, which is fine
			log.Printf("[PERSIST] Note: failed to apply IP %s to %s (may already be configured): %v", ip.IPAddress, ip.InterfaceName, err)
		}
	}

	log.Println("[PERSIST] Custom network interfaces successfully restored.")
}
