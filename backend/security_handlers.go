package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// SuricataAlert represents a parsed Suricata alert from eve.json
type SuricataAlert struct {
	Timestamp   string `json:"timestamp"`
	AlertAction string `json:"alert_action"`
	Signature   string `json:"signature"`
	Severity    int    `json:"severity"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Protocol    string `json:"protocol"`
	Category    string `json:"category"`
}

// CrowdSecDecision represents a CrowdSec blocking decision
type CrowdSecDecision struct {
	ID       int    `json:"id"`
	Source   string `json:"source"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
	Duration string `json:"duration"`
}

// SecurityStats aggregates security statistics
type SecurityStats struct {
	SuricataStats struct {
		TotalAlerts    int      `json:"total_alerts"`
		HighSeverity   int      `json:"high_severity"`
		MediumSeverity int      `json:"medium_severity"`
		LowSeverity    int      `json:"low_severity"`
		TopSignatures  []string `json:"top_signatures"`
		AlertsLastHour int      `json:"alerts_last_hour"`
	} `json:"suricata_stats"`
	CrowdSecStats struct {
		ActiveDecisions int      `json:"active_decisions"`
		BlockedIPs      int      `json:"blocked_ips"`
		TopScenarios    []string `json:"top_scenarios"`
	} `json:"crowdsec_stats"`
}

func getSuricataAlerts(w http.ResponseWriter, r *http.Request) {
	// Read last N lines from eve.json
	limit := 100 // Get last 100 alerts

	eveLogPath := "/var/log/suricata/eve.json"

	// Check if file exists
	if _, err := os.Stat(eveLogPath); os.IsNotExist(err) {
		http.Error(w, "Suricata not installed or eve.json not found", http.StatusNotFound)
		return
	}

	// Use tail command to get last N lines
	output, err := runPrivilegedOutput("tail", "-n", fmt.Sprintf("%d", limit), eveLogPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read Suricata logs: %v", err)
		respondSystemError(w, ErrGenericInternalError, "Failed to read Suricata logs", err)
		return
	}

	alerts := []SuricataAlert{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}

		// Only process alert events
		if eventType, ok := event["event_type"].(string); !ok || eventType != "alert" {
			continue
		}

		alert := SuricataAlert{}

		if ts, ok := event["timestamp"].(string); ok {
			alert.Timestamp = ts
		}

		if alertData, ok := event["alert"].(map[string]interface{}); ok {
			if action, ok := alertData["action"].(string); ok {
				alert.AlertAction = action
			}
			if signature, ok := alertData["signature"].(string); ok {
				alert.Signature = signature
			}
			if severity, ok := alertData["severity"].(float64); ok {
				alert.Severity = int(severity)
			}
			if category, ok := alertData["category"].(string); ok {
				alert.Category = category
			}
		}

		if srcIP, ok := event["src_ip"].(string); ok {
			alert.SrcIP = srcIP
		}
		if srcPort, ok := event["src_port"].(float64); ok {
			alert.SrcPort = int(srcPort)
		}
		if destIP, ok := event["dest_ip"].(string); ok {
			alert.DestIP = destIP
		}
		if destPort, ok := event["dest_port"].(float64); ok {
			alert.DestPort = int(destPort)
		}
		if proto, ok := event["proto"].(string); ok {
			alert.Protocol = proto
		}

		alerts = append(alerts, alert)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func getCrowdSecDecisions(w http.ResponseWriter, r *http.Request) {
	// Execute cscli to get decisions
	output, err := runPrivilegedOutput("cscli", "decisions", "list", "-o", "json")
	if err != nil {
		// CrowdSec might not be installed
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]CrowdSecDecision{})
		return
	}

	var decisions []CrowdSecDecision
	if err := json.Unmarshal(output, &decisions); err != nil {
		log.Printf("[ERROR] Failed to parse CrowdSec decisions: %v", err)
		respondSystemError(w, ErrGenericInternalError, "Failed to parse CrowdSec decisions", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decisions)
}

func getSecurityStats(w http.ResponseWriter, r *http.Request) {
	stats := SecurityStats{}

	// Get Suricata statistics from eve.json
	eveLogPath := "/var/log/suricata/eve.json"
	if _, err := os.Stat(eveLogPath); err == nil {
		output, err := runPrivilegedOutput("tail", "-n", "1000", eveLogPath)
		if err == nil {
			lines := strings.Split(string(output), "\n")
			signatureCounts := make(map[string]int)

			for _, line := range lines {
				if line == "" {
					continue
				}

				var event map[string]interface{}
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					continue
				}

				if eventType, ok := event["event_type"].(string); ok && eventType == "alert" {
					stats.SuricataStats.TotalAlerts++

					if alertData, ok := event["alert"].(map[string]interface{}); ok {
						if severity, ok := alertData["severity"].(float64); ok {
							switch int(severity) {
							case 1:
								stats.SuricataStats.HighSeverity++
							case 2:
								stats.SuricataStats.MediumSeverity++
							case 3:
								stats.SuricataStats.LowSeverity++
							}
						}

						if signature, ok := alertData["signature"].(string); ok {
							signatureCounts[signature]++
						}
					}
				}
			}

			// Get top 5 signatures
			type sigCount struct {
				sig   string
				count int
			}
			var sigList []sigCount
			for sig, count := range signatureCounts {
				sigList = append(sigList, sigCount{sig, count})
			}
			// Simple sort (top 5)
			for i := 0; i < len(sigList) && i < 5; i++ {
				for j := i + 1; j < len(sigList); j++ {
					if sigList[j].count > sigList[i].count {
						sigList[i], sigList[j] = sigList[j], sigList[i]
					}
				}
				stats.SuricataStats.TopSignatures = append(stats.SuricataStats.TopSignatures, sigList[i].sig)
			}
		}
	}

	// Get CrowdSec statistics
	output, err := runPrivilegedOutput("cscli", "decisions", "list", "-o", "json")
	if err == nil {
		var decisions []map[string]interface{}
		if err := json.Unmarshal(output, &decisions); err == nil {
			stats.CrowdSecStats.ActiveDecisions = len(decisions)

			ipSet := make(map[string]bool)
			scenarioCounts := make(map[string]int)

			for _, dec := range decisions {
				if value, ok := dec["value"].(string); ok {
					ipSet[value] = true
				}
				if scenario, ok := dec["scenario"].(string); ok {
					scenarioCounts[scenario]++
				}
			}

			stats.CrowdSecStats.BlockedIPs = len(ipSet)

			// Top scenarios
			for scenario := range scenarioCounts {
				stats.CrowdSecStats.TopScenarios = append(stats.CrowdSecStats.TopScenarios, scenario)
				if len(stats.CrowdSecStats.TopScenarios) >= 5 {
					break
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
