package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// SpeedTestResult stores the result of a speed test run
type SpeedTestResult struct {
	Download  float64   `json:"download"`   // Mbps
	Upload    float64   `json:"upload"`     // Mbps
	Ping      float64   `json:"ping"`       // ms
	Server    string    `json:"server"`     // Server name
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

// speedtest-cli JSON output structure
type speedtestCLIOutput struct {
	Download float64 `json:"download"` // bits per second
	Upload   float64 `json:"upload"`   // bits per second
	Ping     float64 `json:"ping"`     // ms
	Server   struct {
		Name    string `json:"name"`
		Sponsor string `json:"sponsor"`
		Host    string `json:"host"`
	} `json:"server"`
	Timestamp string `json:"timestamp"`
}

var (
	speedTestMutex   sync.Mutex
	speedTestRunning bool
	speedTestHistory []SpeedTestResult
	maxSpeedHistory  = 10
)

// handleSpeedTest runs a speed test and returns results
func handleSpeedTest(w http.ResponseWriter, r *http.Request) {
	// Only one test at a time
	speedTestMutex.Lock()
	if speedTestRunning {
		speedTestMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "busy",
			"error":  "A speed test is already running. Please wait.",
		})
		return
	}
	speedTestRunning = true
	speedTestMutex.Unlock()

	defer func() {
		speedTestMutex.Lock()
		speedTestRunning = false
		speedTestMutex.Unlock()
	}()

	// Run speedtest-cli with JSON output
	output, err := runPrivilegedCombinedOutput("speedtest-cli", "--json", "--secure")

	result := SpeedTestResult{
		Timestamp: time.Now(),
	}

	if err != nil {
		log.Printf("[SPEEDTEST] Failed: %v", err)
		result.Error = "Speed test failed. Is speedtest-cli installed? (apt install speedtest-cli)"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// Parse JSON output
	var cliResult speedtestCLIOutput
	if err := json.Unmarshal(output, &cliResult); err != nil {
		log.Printf("[SPEEDTEST] Failed to parse output: %v", err)
		result.Error = "Failed to parse speed test results"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// Convert from bits/s to Mbps
	result.Download = cliResult.Download / 1_000_000
	result.Upload = cliResult.Upload / 1_000_000
	result.Ping = cliResult.Ping
	result.Server = cliResult.Server.Sponsor
	if result.Server == "" {
		result.Server = cliResult.Server.Name
	}

	// Store in history
	speedTestMutex.Lock()
	speedTestHistory = append(speedTestHistory, result)
	if len(speedTestHistory) > maxSpeedHistory {
		speedTestHistory = speedTestHistory[len(speedTestHistory)-maxSpeedHistory:]
	}
	speedTestMutex.Unlock()

	log.Printf("[SPEEDTEST] Complete: ↓%.1f Mbps ↑%.1f Mbps Ping:%.1fms Server:%s",
		result.Download, result.Upload, result.Ping, result.Server)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// getSpeedTestHistory returns past speed test results
func getSpeedTestHistory(w http.ResponseWriter, r *http.Request) {
	speedTestMutex.Lock()
	history := make([]SpeedTestResult, len(speedTestHistory))
	copy(history, speedTestHistory)
	speedTestMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}
