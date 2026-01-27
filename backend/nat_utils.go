package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// PortForwardingRule represents a single DNAT rule
type PortForwardingRule struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	Protocol     string `json:"protocol"`      // tcp, udp
	ExternalPort int    `json:"external_port"` // Port on WAN interface
	InternalIP   string `json:"internal_ip"`   // IP of identifying host
	InternalPort int    `json:"internal_port"` // Port on internal host
	Enabled      bool   `json:"enabled"`
}

// PortForwardingStore manages the list of rules
type PortForwardingStore struct {
	Rules []PortForwardingRule `json:"rules"`
}

var (
	pfStore      PortForwardingStore
	pfStoreLock  sync.RWMutex
	pfConfigPath = "/etc/softrouter/port_forwarding.json"
)

// initPortForwarding initializes the nftables chains and loads rules
func initPortForwarding() {
	fmt.Println("Initializing Port Forwarding...")

	// ensure softrouter table exists (should be done by firewall init, but good to be safe)
	exec.Command("nft", "add", "table", "inet", "softrouter").Run()

	// Create prerouting chain for DNAT
	// type nat hook prerouting priority -100; policy accept;
	exec.Command("nft", "add", "chain", "inet", "softrouter", "prerouting", "{ type nat hook prerouting priority -100; policy accept; }").Run()

	loadPortForwardingRules()
	applyPortForwardingRules()
}

func loadPortForwardingRules() {
	pfStoreLock.Lock()
	defer pfStoreLock.Unlock()

	data, err := os.ReadFile(pfConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			pfStore.Rules = []PortForwardingRule{} // Init empty
			return
		}
		fmt.Printf("Error loading port forwarding rules: %v\n", err)
		return
	}

	if err := json.Unmarshal(data, &pfStore); err != nil {
		fmt.Printf("Error parsing port forwarding rules: %v\n", err)
		pfStore.Rules = []PortForwardingRule{}
	}
}

func savePortForwardingRules() error {
	pfStoreLock.RLock()
	data, err := json.MarshalIndent(pfStore, "", "  ")
	pfStoreLock.RUnlock()

	if err != nil {
		return err
	}

	return os.WriteFile(pfConfigPath, data, 0644)
}

func applyPortForwardingRules() {
	pfStoreLock.RLock()
	rules := pfStore.Rules
	pfStoreLock.RUnlock()

	fmt.Println("Applying Port Forwarding Rules...")

	// Flush the chain first
	exec.Command("nft", "flush", "chain", "inet", "softrouter", "prerouting").Run()

	// Get WAN interface for iifname filter (optional but recommended to avoid DNAT from LAN)
	// For simplicity in this iteration, we might omit iifname or try to detect it.
	// If we rely on the same detection as firewall_utils, we might need to export that or repeat logic.
	// To keep it robust, let's just apply to all interfaces for now, or assume "eth0"/WAN detection later.
	// Better: Apply to incoming traffic generally.

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// building nft command:
		// nft add rule inet softrouter prerouting [protocol] dport [ext_port] dnat to [int_ip]:[int_port]

		// Validating protocol
		proto := rule.Protocol
		if proto != "tcp" && proto != "udp" {
			proto = "tcp"
		}

		args := []string{
			"add", "rule", "inet", "softrouter", "prerouting",
			proto, "dport", fmt.Sprintf("%d", rule.ExternalPort),
			"dnat", "to", fmt.Sprintf("%s:%d", rule.InternalIP, rule.InternalPort),
		}

		cmd := exec.Command("nft", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("Failed to apply rule %s (%d->%s:%d): %v\nOutput: %s\n",
				rule.ID, rule.ExternalPort, rule.InternalIP, rule.InternalPort, err, string(output))
		} else {
			fmt.Printf("Applied rule: %s %d -> %s:%d\n", proto, rule.ExternalPort, rule.InternalIP, rule.InternalPort)
		}
	}
}

func addPortForwardingRule(rule PortForwardingRule) error {
	pfStoreLock.Lock()

	// Validate/Default Protocol
	if rule.Protocol != "udp" {
		rule.Protocol = "tcp"
	}

	pfStore.Rules = append(pfStore.Rules, rule)
	pfStoreLock.Unlock()

	if err := savePortForwardingRules(); err != nil {
		return err
	}
	applyPortForwardingRules()
	return nil
}

func deletePortForwardingRule(id string) error {
	pfStoreLock.Lock()
	newRules := []PortForwardingRule{}
	found := false
	for _, r := range pfStore.Rules {
		if r.ID == id {
			found = true
			continue
		}
		newRules = append(newRules, r)
	}
	pfStore.Rules = newRules
	pfStoreLock.Unlock()

	if !found {
		return fmt.Errorf("rule not found")
	}

	if err := savePortForwardingRules(); err != nil {
		return err
	}
	applyPortForwardingRules()
	return nil
}
