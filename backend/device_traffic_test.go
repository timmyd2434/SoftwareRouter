package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetDeviceTrafficHandler(t *testing.T) {
	// Populate state for dummy device
	deviceTrafficMu.Lock()
	deviceTrafficMap["192.168.1.105"] = &deviceTrafficState{
		RxBytes: 5000,
		TxBytes: 2000,
		RxRate:  500,
		TxRate:  200,
	}
	deviceTrafficDay["192.168.1.105"] = 7000
	deviceTrafficMu.Unlock()

	defer func() {
		deviceTrafficMu.Lock()
		delete(deviceTrafficMap, "192.168.1.105")
		delete(deviceTrafficDay, "192.168.1.105")
		deviceTrafficMu.Unlock()
	}()

	req, err := http.NewRequest("GET", "/api/traffic/devices", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(getDeviceTraffic)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	var entries []DeviceTrafficEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &entries); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	found := false
	for _, entry := range entries {
		if entry.IP == "192.168.1.105" {
			found = true
			if entry.RxBytes != 5000 || entry.TxBytes != 2000 {
				t.Errorf("Unexpected byte counts: rx=%d, tx=%d", entry.RxBytes, entry.TxBytes)
			}
		}
	}

	if !found {
		t.Errorf("Expected IP 192.168.1.105 to be present in device traffic output")
	}
}
