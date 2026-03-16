package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"
)

// InterfaceSchedule represents a scheduled up/down window for an interface
type InterfaceSchedule struct {
	ID            string   `json:"id"`
	InterfaceName string   `json:"interface_name"`
	DownTime      string   `json:"down_time"` // "HH:MM" 24h local time
	UpTime        string   `json:"up_time"`   // "HH:MM" 24h local time
	Days          []string `json:"days"`      // e.g. ["Mon","Tue","Wed"]
	Enabled       bool     `json:"enabled"`
	Comment       string   `json:"comment"`
}

// ScheduleStore manages persistence
type ScheduleStore struct {
	Schedules []InterfaceSchedule `json:"schedules"`
}

var (
	scheduleStore     ScheduleStore
	scheduleStoreLock sync.RWMutex
	schedulesPath     = "/etc/softrouter/schedules.json"
)

func loadSchedules() {
	scheduleStoreLock.Lock()
	defer scheduleStoreLock.Unlock()

	data, err := os.ReadFile(schedulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			scheduleStore.Schedules = []InterfaceSchedule{}
			return
		}
		log.Printf("Error loading schedules: %v", err)
		return
	}

	if err := json.Unmarshal(data, &scheduleStore); err != nil {
		log.Printf("Error parsing schedules: %v", err)
		scheduleStore.Schedules = []InterfaceSchedule{}
	}
}

func saveSchedules() error {
	scheduleStoreLock.RLock()
	data, err := json.MarshalIndent(scheduleStore, "", "  ")
	scheduleStoreLock.RUnlock()

	if err != nil {
		return err
	}
	return os.WriteFile(schedulesPath, data, 0600)
}

// isValidTime checks "HH:MM" format
func isValidTime(t string) bool {
	if len(t) != 5 || t[2] != ':' {
		return false
	}
	h := (int(t[0]-'0') * 10) + int(t[1]-'0')
	m := (int(t[3]-'0') * 10) + int(t[4]-'0')
	return h >= 0 && h <= 23 && m >= 0 && m <= 59
}

// isValidDay checks a day-of-week string
func isValidDay(d string) bool {
	valid := map[string]bool{
		"Mon": true, "Tue": true, "Wed": true, "Thu": true,
		"Fri": true, "Sat": true, "Sun": true,
	}
	return valid[d]
}

// --- HTTP Handlers ---

func getSchedules(w http.ResponseWriter, r *http.Request) {
	scheduleStoreLock.RLock()
	schedules := scheduleStore.Schedules
	scheduleStoreLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schedules)
}

func createSchedule(w http.ResponseWriter, r *http.Request) {
	var req InterfaceSchedule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate fields
	if req.InterfaceName == "" {
		http.Error(w, "Interface name is required", http.StatusBadRequest)
		return
	}
	if !isValidInterfaceName(req.InterfaceName) {
		http.Error(w, "Invalid interface name", http.StatusBadRequest)
		return
	}
	if !isValidTime(req.DownTime) {
		http.Error(w, "Invalid down_time format (expected HH:MM)", http.StatusBadRequest)
		return
	}
	if !isValidTime(req.UpTime) {
		http.Error(w, "Invalid up_time format (expected HH:MM)", http.StatusBadRequest)
		return
	}
	if len(req.Days) == 0 {
		http.Error(w, "At least one day must be selected", http.StatusBadRequest)
		return
	}
	for _, d := range req.Days {
		if !isValidDay(d) {
			http.Error(w, fmt.Sprintf("Invalid day: %s", d), http.StatusBadRequest)
			return
		}
	}

	// Generate ID
	req.ID = uuid.New().String()

	scheduleStoreLock.Lock()
	scheduleStore.Schedules = append(scheduleStore.Schedules, req)
	scheduleStoreLock.Unlock()

	if err := saveSchedules(); err != nil {
		http.Error(w, "Failed to save schedule", http.StatusInternalServerError)
		return
	}

	logAuditEvent(getUsernameFromToken(r), "schedule.create",
		req.InterfaceName,
		fmt.Sprintf("{\"down\":\"%s\",\"up\":\"%s\"}", req.DownTime, req.UpTime),
		getClientIP(r), true)

	log.Printf("Schedule created: %s %s down=%s up=%s", req.ID, req.InterfaceName, req.DownTime, req.UpTime)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

func updateSchedule(w http.ResponseWriter, r *http.Request) {
	var req InterfaceSchedule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "Schedule ID is required", http.StatusBadRequest)
		return
	}

	// Validate fields
	if req.InterfaceName != "" && !isValidInterfaceName(req.InterfaceName) {
		http.Error(w, "Invalid interface name", http.StatusBadRequest)
		return
	}
	if req.DownTime != "" && !isValidTime(req.DownTime) {
		http.Error(w, "Invalid down_time format (expected HH:MM)", http.StatusBadRequest)
		return
	}
	if req.UpTime != "" && !isValidTime(req.UpTime) {
		http.Error(w, "Invalid up_time format (expected HH:MM)", http.StatusBadRequest)
		return
	}
	for _, d := range req.Days {
		if !isValidDay(d) {
			http.Error(w, fmt.Sprintf("Invalid day: %s", d), http.StatusBadRequest)
			return
		}
	}

	scheduleStoreLock.Lock()
	found := false
	for i, s := range scheduleStore.Schedules {
		if s.ID == req.ID {
			scheduleStore.Schedules[i] = req
			found = true
			break
		}
	}
	scheduleStoreLock.Unlock()

	if !found {
		http.Error(w, "Schedule not found", http.StatusNotFound)
		return
	}

	if err := saveSchedules(); err != nil {
		http.Error(w, "Failed to save schedule", http.StatusInternalServerError)
		return
	}

	logAuditEvent(getUsernameFromToken(r), "schedule.update",
		req.InterfaceName,
		fmt.Sprintf("{\"id\":\"%s\"}", req.ID),
		getClientIP(r), true)

	log.Printf("Schedule updated: %s", req.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

func deleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	scheduleStoreLock.Lock()
	var newSchedules []InterfaceSchedule
	found := false
	for _, s := range scheduleStore.Schedules {
		if s.ID == id {
			found = true
			continue
		}
		newSchedules = append(newSchedules, s)
	}
	scheduleStore.Schedules = newSchedules
	scheduleStoreLock.Unlock()

	if !found {
		http.Error(w, "Schedule not found", http.StatusNotFound)
		return
	}

	if err := saveSchedules(); err != nil {
		http.Error(w, "Failed to save schedule", http.StatusInternalServerError)
		return
	}

	logAuditEvent(getUsernameFromToken(r), "schedule.delete",
		id, "{}", getClientIP(r), true)

	log.Printf("Schedule deleted: %s", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
