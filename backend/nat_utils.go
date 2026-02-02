package main

import (
	"encoding/json"
	"fmt"
	"os"
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
	runPrivileged("nft", "add", "table", "inet", "softrouter")

	// Create prerouting chain for DNAT
	// type nat hook prerouting priority -100; policy accept;
	runPrivileged("nft", "add", "chain", "inet", "softrouter", "prerouting", "{ type nat hook prerouting priority -100; policy accept; }")

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

func GetPortForwardingRules() []PortForwardingRule {
	pfStoreLock.RLock()
	defer pfStoreLock.RUnlock()
	// Return a copy to avoid races if caller modifies
	rules := make([]PortForwardingRule, len(pfStore.Rules))
	copy(rules, pfStore.Rules)
	return rules
}

func applyPortForwardingRules() {
	// Delegate to FirewallManager
	firewallManager.ApplyFirewallRules()
}

// Deprecated and REMOVED for security reasons
// applyPortForwardingRulesLegacy used unguarded exec.Command calls
// All port forwarding now goes through FirewallManager.ApplyFirewallRules()

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

func updatePortForwardingRule(id string, updatedRule PortForwardingRule) error {
	pfStoreLock.Lock()
	found := false

	// Validate/Default Protocol
	if updatedRule.Protocol != "udp" {
		updatedRule.Protocol = "tcp"
	}

	for i, r := range pfStore.Rules {
		if r.ID == id {
			// Keep the same ID and enabled status
			updatedRule.ID = id
			if updatedRule.Enabled == false && r.Enabled == false {
				// Preserve enabled status if not explicitly set
				updatedRule.Enabled = r.Enabled
			}
			pfStore.Rules[i] = updatedRule
			found = true
			break
		}
	}
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
