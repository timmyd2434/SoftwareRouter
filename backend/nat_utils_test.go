package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPortForwardingDualFormatLoading(t *testing.T) {
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "port_forwarding.json")

	// Save original config path and restore after test
	pfStoreLock.Lock()
	origPath := pfConfigPath
	origRules := pfStore.Rules
	pfConfigPath = tmpPath
	pfStoreLock.Unlock()

	defer func() {
		pfStoreLock.Lock()
		pfConfigPath = origPath
		pfStore.Rules = origRules
		pfStoreLock.Unlock()
	}()

	rule1 := PortForwardingRule{
		ID:           "test-1",
		Description:  "Web Server",
		Protocol:     "tcp",
		ExternalPort: 8080,
		InternalIP:   "192.168.1.100",
		InternalPort: 80,
		Enabled:      true,
	}

	// 1. Test Struct/Object Format {"rules": [...]}
	objData, err := json.Marshal(PortForwardingStore{Rules: []PortForwardingRule{rule1}})
	if err != nil {
		t.Fatalf("Failed to marshal object format: %v", err)
	}
	if err := os.WriteFile(tmpPath, objData, 0600); err != nil {
		t.Fatalf("Failed to write object format file: %v", err)
	}

	loadPortForwardingRules()
	rules := GetPortForwardingRules()
	if len(rules) != 1 || rules[0].ID != "test-1" {
		t.Errorf("Expected 1 rule from object format, got %v", rules)
	}

	// 2. Test Array Format [...]
	arrData, err := json.Marshal([]PortForwardingRule{rule1})
	if err != nil {
		t.Fatalf("Failed to marshal array format: %v", err)
	}
	if err := os.WriteFile(tmpPath, arrData, 0600); err != nil {
		t.Fatalf("Failed to write array format file: %v", err)
	}

	loadPortForwardingRules()
	rules = GetPortForwardingRules()
	if len(rules) != 1 || rules[0].ID != "test-1" {
		t.Errorf("Expected 1 rule from array format, got %v", rules)
	}

	// 3. Test Invalid JSON Corrupted File (Must not wipe in-memory rules)
	if err := os.WriteFile(tmpPath, []byte("invalid json..."), 0600); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	loadPortForwardingRules()
	rules = GetPortForwardingRules()
	if len(rules) != 1 || rules[0].ID != "test-1" {
		t.Errorf("Expected in-memory rules to be preserved on parse error, got %v", rules)
	}
}

func TestSavePortForwardingRulesAtomic(t *testing.T) {
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "port_forwarding.json")

	pfStoreLock.Lock()
	origPath := pfConfigPath
	origRules := pfStore.Rules
	pfConfigPath = tmpPath
	pfStore.Rules = []PortForwardingRule{
		{
			ID:           "atomic-1",
			Description:  "SSH Forward",
			Protocol:     "tcp",
			ExternalPort: 2222,
			InternalIP:   "192.168.1.50",
			InternalPort: 22,
			Enabled:      true,
		},
	}
	pfStoreLock.Unlock()

	defer func() {
		pfStoreLock.Lock()
		pfConfigPath = origPath
		pfStore.Rules = origRules
		pfStoreLock.Unlock()
	}()

	if err := savePortForwardingRules(); err != nil {
		t.Fatalf("savePortForwardingRules failed: %v", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("Failed to read saved file: %v", err)
	}

	var store PortForwardingStore
	if err := json.Unmarshal(data, &store); err != nil {
		t.Fatalf("Failed to unmarshal saved atomic file: %v", err)
	}

	if len(store.Rules) != 1 || store.Rules[0].ID != "atomic-1" {
		t.Errorf("Unexpected rules in saved file: %v", store.Rules)
	}
}
