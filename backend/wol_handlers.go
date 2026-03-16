package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// handleWakeOnLAN handles sending a Wake-on-LAN packet
func handleWakeOnLAN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MACAddress string `json:"macAddress"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondInvalidRequest(w, "Invalid request body")
		return
	}

	if req.MACAddress == "" {
		http.Error(w, "MAC address is required", http.StatusBadRequest)
		return
	}

	// Send Wake-on-LAN packet
	if err := SendWakeOnLAN(req.MACAddress); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to send Wake-on-LAN packet", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Wake-on-LAN packet sent to %s", req.MACAddress),
	})
}

// handleGetWoLDevices returns all saved devices
func handleGetWoLDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	store, err := loadWoLDevices()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to load devices", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.Devices)
}

// handleSaveWoLDevice saves a new device
func handleSaveWoLDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newDevice WoLDevice
	if err := json.NewDecoder(r.Body).Decode(&newDevice); err != nil {
		respondInvalidRequest(w, "Invalid request body")
		return
	}

	// Validate device
	if err := validateWoLDevice(newDevice); err != nil {
		respondInvalidRequest(w, "Validation failed")
		return
	}

	// Format MAC address
	formatted, err := FormatMAC(newDevice.MACAddress)
	if err != nil {
		respondInvalidRequest(w, "Invalid MAC address")
		return
	}
	newDevice.MACAddress = formatted

	// Load existing devices
	store, err := loadWoLDevices()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to load devices", err)
		return
	}

	// Check for duplicate name
	if existing := getDeviceByName(store, newDevice.Name); existing != nil {
		http.Error(w, fmt.Sprintf("Device with name '%s' already exists", newDevice.Name), http.StatusConflict)
		return
	}

	// Add device
	store.Devices = append(store.Devices, newDevice)

	// Save to disk
	if err := saveWoLDevices(store); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save devices", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Device saved",
	})
}

// handleDeleteWoLDevice deletes a saved device
func handleDeleteWoLDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Device name is required", http.StatusBadRequest)
		return
	}

	// Load existing devices
	store, err := loadWoLDevices()
	if err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to load devices", err)
		return
	}

	// Find and remove device
	found := false
	newDevices := []WoLDevice{}
	for _, device := range store.Devices {
		if strings.EqualFold(device.Name, name) {
			found = true
			continue // Skip this device (delete it)
		}
		newDevices = append(newDevices, device)
	}

	if !found {
		http.Error(w, fmt.Sprintf("Device '%s' not found", name), http.StatusNotFound)
		return
	}

	store.Devices = newDevices

	// Save to disk
	if err := saveWoLDevices(store); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to save devices", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Device deleted",
	})
}
