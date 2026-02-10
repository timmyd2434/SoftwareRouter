package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WoLDevice represents a saved Wake-on-LAN device
type WoLDevice struct {
	Name       string `json:"name"`       // e.g., "Office Desktop"
	MACAddress string `json:"macAddress"` // e.g., "AA:BB:CC:DD:EE:FF"
	IPAddress  string `json:"ipAddress"`  // Optional, for reference only
}

// WoLStore holds all saved WoL devices
type WoLStore struct {
	Devices []WoLDevice `json:"devices"`
}

const wolDevicesPath = "/etc/softrouter/wol_devices.json"

// loadWoLDevices loads saved devices from disk
func loadWoLDevices() (*WoLStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(wolDevicesPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(wolDevicesPath); os.IsNotExist(err) {
		// Return empty store if file doesn't exist
		return &WoLStore{Devices: []WoLDevice{}}, nil
	}

	data, err := os.ReadFile(wolDevicesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read devices file: %w", err)
	}

	var store WoLStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("failed to parse devices JSON: %w", err)
	}

	return &store, nil
}

// saveWoLDevices saves devices to disk
func saveWoLDevices(store *WoLStore) error {
	// Ensure directory exists
	dir := filepath.Dir(wolDevicesPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal devices: %w", err)
	}

	if err := os.WriteFile(wolDevicesPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write devices file: %w", err)
	}

	return nil
}

// validateWoLDevice validates a WoL device
func validateWoLDevice(device WoLDevice) error {
	if device.Name == "" {
		return fmt.Errorf("device name is required")
	}

	// Validate MAC address by attempting to parse it
	_, err := parseMAC(device.MACAddress)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	// Format MAC address to standard format
	formatted, err := FormatMAC(device.MACAddress)
	if err != nil {
		return err
	}
	device.MACAddress = formatted

	return nil
}

// getDeviceByName finds a device by name (case-insensitive)
func getDeviceByName(store *WoLStore, name string) *WoLDevice {
	for i := range store.Devices {
		if strings.EqualFold(store.Devices[i].Name, name) {
			return &store.Devices[i]
		}
	}
	return nil
}
