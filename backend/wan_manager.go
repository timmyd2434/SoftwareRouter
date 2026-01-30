package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

// WANInterface represents a WAN connection configuration
type WANInterface struct {
	Interface   string `json:"interface"`    // e.g., "eth0", "eth1"
	Name        string `json:"name"`         // e.g., "Primary Fiber", "Backup 5G"
	Gateway     string `json:"gateway"`      // e.g., "192.168.1.1"
	CheckTarget string `json:"check_target"` // e.g., "8.8.8.8"
	Priority    int    `json:"priority"`     // Lower is higher priority (1 = Primary)
	Weight      int    `json:"weight"`       // For Load Balancing (default 1)
	Enabled     bool   `json:"enabled"`
	State       string `json:"state"` // "online", "offline", "unknown"
}

// WANStore manages persistence
type WANStore struct {
	Mode       string         `json:"mode"` // "failover" or "load_balance"
	Interfaces []WANInterface `json:"interfaces"`
}

var (
	wanStore      WANStore
	wanLock       sync.RWMutex
	wanConfigPath = "/etc/softrouter/multi_wan.json"
	wanTicker     *time.Ticker
	currentActive string // Interface name of currently active WAN (for active-passive)
)

func initWANManager() {
	loadWANConfig()
	startWANMonitor()
}

func loadWANConfig() {
	wanLock.Lock()
	defer wanLock.Unlock()

	data, err := os.ReadFile(wanConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			wanStore.Interfaces = []WANInterface{}
			wanStore.Mode = "failover"
			return
		}
		fmt.Printf("Error loading WAN config: %v\n", err)
		return
	}

	if err := json.Unmarshal(data, &wanStore); err != nil {
		fmt.Printf("Error parsing WAN config: %v\n", err)
		wanStore.Interfaces = []WANInterface{}
		wanStore.Mode = "failover"
	}
}

func saveWANConfig() error {
	wanLock.RLock()
	data, err := json.MarshalIndent(wanStore, "", "  ")
	wanLock.RUnlock()

	if err != nil {
		return err
	}
	return os.WriteFile(wanConfigPath, data, 0644)
}

// startWANMonitor runs the periodic health check
func startWANMonitor() {
	wanTicker = time.NewTicker(10 * time.Second) // Check every 10s
	go func() {
		for range wanTicker.C {
			checkWANHealth()
		}
	}()
	fmt.Println("WAN Monitor started.")
}

func checkWANHealth() {
	wanLock.Lock()
	interfaces := wanStore.Interfaces
	mode := wanStore.Mode
	wanLock.Unlock() // Unlock logic to avoid holding during long pings

	updated := false

	// Check all interfaces
	for i := range interfaces {
		if !interfaces[i].Enabled {
			continue
		}

		target := interfaces[i].CheckTarget
		if target == "" {
			target = "8.8.8.8" // Default
		}

		// -W 2 seconds timeout
		cmd := exec.Command("ping", "-I", interfaces[i].Interface, "-c", "1", "-W", "2", target)
		err := cmd.Run()

		isOnline := (err == nil)
		newState := "offline"
		if isOnline {
			newState = "online"
		}

		if interfaces[i].State != newState {
			interfaces[i].State = newState
			updated = true
			fmt.Printf("WAN Interface %s (%s) is now %s\n", interfaces[i].Name, interfaces[i].Interface, newState)
		}
	}

	// Update Store if states changed
	if updated {
		wanLock.Lock()
		wanStore.Interfaces = interfaces
		wanLock.Unlock()
	}

	// Apply Routing Decision
	applyRoutingLogic(interfaces, mode)
}

func applyRoutingLogic(interfaces []WANInterface, mode string) {
	if mode == "load_balance" {
		applyLoadBalancing(interfaces)
	} else {
		applyFailover(interfaces)
	}
}

func applyFailover(interfaces []WANInterface) {
	bestInterface := ""
	highestPriority := 999

	for _, iface := range interfaces {
		if iface.Enabled && iface.State == "online" {
			if iface.Priority < highestPriority {
				highestPriority = iface.Priority
				bestInterface = iface.Interface
			}
		}
	}

	if bestInterface != "" && bestInterface != currentActive {
		fmt.Printf("Failover: Switching default gateway to %s\n", bestInterface)
		switchDefaultRoute(bestInterface)
	} else if bestInterface == "" {
		// All offline?
		// currentActive might stay as last known regular
	}
}

func applyLoadBalancing(interfaces []WANInterface) {
	// Gather all online interfaces
	var onlineInterfaces []WANInterface
	for _, iface := range interfaces {
		if iface.Enabled && iface.State == "online" {
			onlineInterfaces = append(onlineInterfaces, iface)
		}
	}

	if len(onlineInterfaces) == 0 {
		return // Nothing to do
	}

	// Build ip route command
	// ip route replace default scope global
	//   nexthop via <G1> dev <I1> weight <W1>
	//   nexthop via <G2> dev <I2> weight <W2>

	args := []string{"route", "replace", "default", "scope", "global"}

	for _, iface := range onlineInterfaces {
		weight := iface.Weight
		if weight <= 0 {
			weight = 1
		}
		args = append(args, "nexthop", "via", iface.Gateway, "dev", iface.Interface, "weight", fmt.Sprintf("%d", weight))
	}

	// Check if this is different from current state?
	// For simplicity, we re-apply. Linux is smart enough to handle replace.
	// But to avoid log spam, maybe only log if changes?
	// Note: 'replace' is atomic.

	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to apply Load Balancing: %v (%s)\n", err, string(out))
	} else {
		// Success
		// fmt.Println("Applied Load Balancing routes.")
	}
	currentActive = "balanced"
}

func switchDefaultRoute(ifaceName string) {
	// Find gateway for this interface
	wanLock.RLock()
	gateway := ""
	for _, iface := range wanStore.Interfaces {
		if iface.Interface == ifaceName {
			gateway = iface.Gateway
			break
		}
	}
	wanLock.RUnlock()

	if gateway == "" {
		fmt.Printf("Error: No gateway found for interface %s, cannot switch route.\n", ifaceName)
		return
	}

	cmd := exec.Command("ip", "route", "replace", "default", "via", gateway, "dev", ifaceName)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Failed to switch default route: %v (%s)\n", err, string(out))
	} else {
		fmt.Printf("Successfully switched default route to %s via %s\n", ifaceName, gateway)
		currentActive = ifaceName
	}
}

// --- API Handlers ---

func getWANInterfaces(w http.ResponseWriter, r *http.Request) {
	wanLock.RLock()
	// Return the whole store structure now (Mode + Interfaces)
	data := wanStore
	wanLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func updateWANInterfaces(w http.ResponseWriter, r *http.Request) {
	var req WANStore
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	wanLock.Lock()
	wanStore = req
	wanLock.Unlock()

	if err := saveWANConfig(); err != nil {
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	// Trigger immediate check to apply changes
	go checkWANHealth()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}
