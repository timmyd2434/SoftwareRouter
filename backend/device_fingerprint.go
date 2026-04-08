package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	ouiData    = make(map[string]string)
	ouiDataMu  sync.RWMutex
	ouiEnabled bool
)

// initDeviceFingerprint loads the OUI database asynchronously so it doesn't block startup
func initDeviceFingerprint() {
	go loadOUIDatabase()
}

func loadOUIDatabase() {
	// Usually located in /usr/share/ieee-data/oui.txt on Debian/Ubuntu
	path := "/usr/share/ieee-data/oui.txt"
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[FINGERPRINT] Warning: Could not open %s: %v. OUI lookup will be disabled.", path, err)
		return
	}
	defer file.Close()

	ouiDataMu.Lock()
	defer ouiDataMu.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Looks like:
		// E0-43-DB   (hex)		Shenzhen ViewAt Technology Co.,Ltd.
		if strings.Contains(line, "(hex)") {
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) == 2 {
				macPrefix := strings.TrimSpace(parts[0])
				// Standardize to AA:BB:CC
				macPrefix = strings.ReplaceAll(macPrefix, "-", ":")
				vendor := strings.TrimSpace(parts[1])
				
				ouiData[strings.ToUpper(macPrefix)] = vendor
			}
		}
	}

	ouiEnabled = true
	log.Printf("[FINGERPRINT] Loaded %d MAC vendor signatures.", len(ouiData))
}

// lookUpVendor returns the vendor string for a given MAC address (e.g. AA:BB:CC:DD:EE:FF)
func lookUpVendor(mac string) string {
	ouiDataMu.RLock()
	defer ouiDataMu.RUnlock()

	if !ouiEnabled || len(mac) < 8 {
		return "Unknown Vendor"
	}

	prefix := strings.ToUpper(mac[:8]) // AA:BB:CC
	if vendor, ok := ouiData[prefix]; ok {
		return vendor
	}
	return "Unknown Vendor"
}

// DeviceMeta helps store friendly names and icons for devices
type DeviceMeta struct {
	MAC      string `json:"mac"`
	Name     string `json:"name"`
	Type     string `json:"type"` // "desktop", "laptop", "mobile", "iot", "tv", "unknown"
}

var (
	deviceMetaMu sync.RWMutex
	deviceMetas  = make(map[string]DeviceMeta)
)

const deviceMetaFile = "/etc/softrouter/devices_meta.json"

func init() {
	loadDeviceMetas()
}

func loadDeviceMetas() {
	data, err := os.ReadFile(deviceMetaFile)
	if err != nil {
		return
	}
	var metas []DeviceMeta
	if err := json.Unmarshal(data, &metas); err == nil {
		deviceMetaMu.Lock()
		for _, m := range metas {
			deviceMetas[strings.ToUpper(m.MAC)] = m
		}
		deviceMetaMu.Unlock()
	}
}

func saveDeviceMetas() {
	deviceMetaMu.RLock()
	var metas []DeviceMeta
	for _, m := range deviceMetas {
		metas = append(metas, m)
	}
	deviceMetaMu.RUnlock()

	data, _ := json.MarshalIndent(metas, "", "  ")
	os.WriteFile(deviceMetaFile, data, 0600)
}

func updateDeviceMetaHandler(w http.ResponseWriter, r *http.Request) {
	var meta DeviceMeta
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		http.Error(w, "Invalid device data", http.StatusBadRequest)
		return
	}

	meta.MAC = strings.ToUpper(meta.MAC)

	deviceMetaMu.Lock()
	deviceMetas[meta.MAC] = meta
	deviceMetaMu.Unlock()

	go saveDeviceMetas()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// GetDeviceFingerprint returns vendor and user-assigned metadata for a MAC
func GetDeviceFingerprint(mac string) (vendor string, name string, devType string) {
	macUpper := strings.ToUpper(mac)
	vendor = lookUpVendor(macUpper)
	
	deviceMetaMu.RLock()
	defer deviceMetaMu.RUnlock()
	if meta, exists := deviceMetas[macUpper]; exists {
		if meta.Name != "" {
			name = meta.Name
		}
		if meta.Type != "" {
			devType = meta.Type
		}
	}
	
	if devType == "" {
		devType = "unknown"
	}
	
	return vendor, name, devType
}
