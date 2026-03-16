package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// schedulerState tracks whether each schedule's interface is currently
// in the "down" state so we don't spam redundant ip-link calls.
var (
	schedulerApplied   = make(map[string]string) // schedule ID -> "down" or "up"
	schedulerAppliedMu sync.Mutex
)

// initScheduler loads saved schedules and starts the background ticker.
func initScheduler() {
	loadSchedules()
	log.Println("Interface scheduler started")
	go scheduleLoop()
}

// scheduleLoop runs every 30 seconds and evaluates all enabled schedules.
func scheduleLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Run once immediately on startup
	evaluateSchedules()

	for range ticker.C {
		evaluateSchedules()
	}
}

// evaluateSchedules checks every enabled schedule against the current time.
func evaluateSchedules() {
	now := time.Now()
	currentDay := now.Weekday().String()[:3] // "Mon", "Tue", ...
	currentMinutes := now.Hour()*60 + now.Minute()

	scheduleStoreLock.RLock()
	schedules := make([]InterfaceSchedule, len(scheduleStore.Schedules))
	copy(schedules, scheduleStore.Schedules)
	scheduleStoreLock.RUnlock()

	for _, sched := range schedules {
		if !sched.Enabled {
			// If the schedule was just disabled, make sure interface is up
			schedulerAppliedMu.Lock()
			prev, exists := schedulerApplied[sched.ID]
			if exists && prev == "down" {
				log.Printf("Schedule %s disabled — restoring interface %s to up", sched.ID, sched.InterfaceName)
				applyInterfaceState(sched.InterfaceName, "up")
				delete(schedulerApplied, sched.ID)
			}
			schedulerAppliedMu.Unlock()
			continue
		}

		// Check if today is a scheduled day
		dayMatch := false
		for _, d := range sched.Days {
			if d == currentDay {
				dayMatch = true
				break
			}
		}

		downMinutes := parseTimeToMinutes(sched.DownTime)
		upMinutes := parseTimeToMinutes(sched.UpTime)
		if downMinutes < 0 || upMinutes < 0 {
			continue // invalid time, skip
		}

		// Determine desired state
		var desiredState string
		if dayMatch && isInDownWindow(currentMinutes, downMinutes, upMinutes) {
			desiredState = "down"
		} else {
			desiredState = "up"
		}

		// Apply only if state changed
		schedulerAppliedMu.Lock()
		prev := schedulerApplied[sched.ID]
		if prev != desiredState {
			log.Printf("Schedule %s: setting %s to %s (down=%s up=%s)",
				sched.ID, sched.InterfaceName, desiredState, sched.DownTime, sched.UpTime)
			applyInterfaceState(sched.InterfaceName, desiredState)
			schedulerApplied[sched.ID] = desiredState
		}
		schedulerAppliedMu.Unlock()
	}
}

// isInDownWindow returns true if currentMinutes falls within the down window.
// Handles overnight windows (e.g., down at 22:00, up at 06:00).
func isInDownWindow(current, down, up int) bool {
	if down < up {
		// Same-day window: e.g. 08:00 – 17:00
		return current >= down && current < up
	}
	// Overnight window: e.g. 22:00 – 06:00
	return current >= down || current < up
}

// parseTimeToMinutes converts "HH:MM" to minutes since midnight, or -1 on error.
func parseTimeToMinutes(t string) int {
	if len(t) != 5 || t[2] != ':' {
		return -1
	}
	h := (int(t[0]-'0') * 10) + int(t[1]-'0')
	m := (int(t[3]-'0') * 10) + int(t[4]-'0')
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return -1
	}
	return h*60 + m
}

// applyInterfaceState brings an interface up or down.
func applyInterfaceState(iface, state string) {
	if output, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", iface, state); err != nil {
		log.Printf("ERROR: scheduler failed to set %s %s: %v (output: %s)", iface, state, err, string(output))
	} else {
		fmt.Printf("Scheduler: interface %s set to %s\n", iface, state)
	}
}
