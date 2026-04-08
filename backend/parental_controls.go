package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// ParentalPolicy defines a block list for specific devices, optionally scheduled
type ParentalPolicy struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	MACAddresses []string `json:"mac_addresses"`
	Enabled      bool     `json:"enabled"`
	Scheduled    bool     `json:"scheduled"`
	StartTime    string   `json:"start_time"` // "HH:MM"
	EndTime      string   `json:"end_time"`   // "HH:MM"
	DaysOfWeek   []int    `json:"days_of_week"` // 0 = Sunday, 1 = Monday, etc.
}

type ParentalConfig struct {
	Policies []ParentalPolicy `json:"policies"`
}

var (
	parentalMu     sync.RWMutex
	parentalConfig ParentalConfig
	parentalActive map[string]bool // ID -> currently blocking or not
)

const parentalConfigFile = "/etc/softrouter/parental.json"

func initParentalControls() {
	parentalActive = make(map[string]bool)
	if err := loadParentalConfig(); err != nil {
		log.Printf("[PARENTAL] Info: creating default config (%v)", err)
		parentalConfig = ParentalConfig{Policies: []ParentalPolicy{}}
		saveParentalConfig()
	}

	go parentalLoop()
}

func loadParentalConfig() error {
	parentalMu.Lock()
	defer parentalMu.Unlock()

	data, err := os.ReadFile(parentalConfigFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &parentalConfig)
}

func saveParentalConfig() error {
	parentalMu.Lock()
	defer parentalMu.Unlock()

	data, err := json.MarshalIndent(parentalConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(parentalConfigFile, data, 0600)
}

// evalParentalSchedules checks if policies need to turn on or off based on schedule
func evalParentalSchedules() {
	now := time.Now()
	currentDay := int(now.Weekday())
	currentMins := now.Hour()*60 + now.Minute()

	var needsApply bool

	parentalMu.Lock()
	for _, p := range parentalConfig.Policies {
		shouldBlock := p.Enabled

		if p.Enabled && p.Scheduled {
			var dayMatch bool
			for _, d := range p.DaysOfWeek {
				if d == currentDay {
					dayMatch = true
					break
				}
			}

			if !dayMatch {
				shouldBlock = false
			} else {
				startMins := parseTimeMapToMins(p.StartTime)
				endMins := parseTimeMapToMins(p.EndTime)

				if startMins < endMins {
					shouldBlock = currentMins >= startMins && currentMins < endMins
				} else {
					// Spans midnight (e.g. 22:00 to 07:00)
					shouldBlock = currentMins >= startMins || currentMins < endMins
				}
			}
		}

		if parentalActive[p.ID] != shouldBlock {
			parentalActive[p.ID] = shouldBlock
			needsApply = true
			state := "unblocked"
			if shouldBlock {
				state = "blocked"
			}
			log.Printf("[PARENTAL] Policy '%s' is now %s", p.Name, state)
		}
	}
	parentalMu.Unlock()

	// Re-apply firewall rules if a state changed
	if needsApply {
		// Asynchronous apply so we don't block the ticker
		go firewallManager.ApplyFirewallRules()
	}
}

func parseTimeMapToMins(t string) int {
	var h, m int
	fmt.Sscanf(t, "%d:%d", &h, &m)
	return h*60 + m
}

func parentalLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Eval once at startup
	evalParentalSchedules()

	for range ticker.C {
		evalParentalSchedules()
	}
}

// GetActiveBlockedMACs returns a slice of MAC addresses that are currently actively blocked
func GetActiveBlockedMACs() []string {
	parentalMu.RLock()
	defer parentalMu.RUnlock()

	var macs []string
	seen := make(map[string]bool)

	for _, p := range parentalConfig.Policies {
		if parentalActive[p.ID] {
			for _, mac := range p.MACAddresses {
				if !seen[mac] {
					macs = append(macs, mac)
					seen[mac] = true
				}
			}
		}
	}

	return macs
}

// API Handlers
func getParentalConfigHandler(w http.ResponseWriter, r *http.Request) {
	parentalMu.RLock()
	defer parentalMu.RUnlock()

	// Create a safe copy to append active state
	type PlcyResp struct {
		ParentalPolicy
		Active bool `json:"active"`
	}

	resp := struct {
		Policies []PlcyResp `json:"policies"`
	}{}

	for _, p := range parentalConfig.Policies {
		pr := PlcyResp{
			ParentalPolicy: p,
			Active:         parentalActive[p.ID],
		}
		resp.Policies = append(resp.Policies, pr)
	}

	if resp.Policies == nil {
		resp.Policies = []PlcyResp{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func updateParentalConfigHandler(w http.ResponseWriter, r *http.Request) {
	var newCfg ParentalConfig
	if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
		http.Error(w, "Invalid config JSON", http.StatusBadRequest)
		return
	}

	parentalMu.Lock()
	parentalConfig = newCfg
	parentalMu.Unlock()

	if err := saveParentalConfig(); err != nil {
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	// Re-eval immediately
	evalParentalSchedules()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
