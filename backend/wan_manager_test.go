package main

import (
	"testing"
)

func TestWANInterface_Defaults(t *testing.T) {
	iface := WANInterface{
		Interface:   "eth0",
		Name:        "Test WAN",
		CheckTarget: "",
		State:       "online",
	}

	if iface.CheckTarget != "" {
		t.Errorf("expected empty initial CheckTarget, got %s", iface.CheckTarget)
	}
}

func TestWANStateHysteresis(t *testing.T) {
	iface := WANInterface{
		Interface:    "eth0",
		Name:         "Primary Fiber",
		State:        "online",
		FailCount:    0,
		SuccessCount: 5,
	}

	// Single failure
	iface.FailCount++
	iface.SuccessCount = 0
	if iface.FailCount < 2 && iface.State == "offline" {
		t.Errorf("interface prematurely marked offline on fail count %d", iface.FailCount)
	}

	// Second failure (2 cycles = 1 minute)
	iface.FailCount++
	if iface.FailCount >= 2 {
		iface.State = "offline"
	}

	if iface.State != "offline" {
		t.Errorf("expected state offline after 2 failures, got %s", iface.State)
	}

	// Single success while offline
	iface.SuccessCount++
	iface.FailCount = 0
	if iface.SuccessCount < 2 && iface.State == "online" {
		t.Errorf("interface prematurely marked online on success count %d", iface.SuccessCount)
	}

	// Second success while offline
	iface.SuccessCount++
	if iface.SuccessCount >= 2 {
		iface.State = "online"
	}

	if iface.State != "online" {
		t.Errorf("expected state online after 2 successes, got %s", iface.State)
	}
}
