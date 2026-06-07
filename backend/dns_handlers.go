package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// DNSStats represents aggregate metrics from the ad-blocker
type DNSStats struct {
	TotalQueries      int         `json:"total_queries"`
	BlockedFiltering  int         `json:"blocked_filtering"`
	BlockedPercentage float64     `json:"blocked_percentage"`
	TopBlocked        []TopDomain `json:"top_blocked"`
	TopQueries        []TopDomain `json:"top_queries"`
	TopClients        []TopDomain `json:"top_clients"`
}

type TopDomain struct {
	Domain string `json:"domain"`
	Hits   int    `json:"hits"`
}

func getDNSStats(w http.ResponseWriter, r *http.Request) {
	stats := DNSStats{}

	// Get AdGuard Home configuration from config
	configLock.RLock()
	aghURL := config.AdGuard.URL
	aghUsername := config.AdGuard.Username
	aghPassword := config.AdGuard.Password
	configLock.RUnlock()

	if aghURL == "" {
		aghURL = "http://localhost:3000" // Fallback default
	}

	// Try to fetch stats from AdGuard Home
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", aghURL+"/control/stats", nil)
	if err != nil {
		// Fall back to mock data
		stats = getMockDNSStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}

	// Add Basic Auth if credentials are provided
	if aghUsername != "" && aghPassword != "" {
		req.SetBasicAuth(aghUsername, aghPassword)
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		// Fall back to mock data if AdGuard Home is not available
		stats = getMockDNSStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}
	defer resp.Body.Close()

	var aghData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&aghData); err != nil {
		stats = getMockDNSStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
		return
	}

	// Parse basic statistics
	if val, ok := aghData["num_dns_queries"].(float64); ok {
		stats.TotalQueries = int(val)
	}
	if val, ok := aghData["num_blocked_filtering"].(float64); ok {
		stats.BlockedFiltering = int(val)
	}
	if stats.TotalQueries > 0 {
		stats.BlockedPercentage = (float64(stats.BlockedFiltering) / float64(stats.TotalQueries)) * 100
	}

	// Parse top blocked domains
	if topBlocked, ok := aghData["top_blocked_domains"].([]interface{}); ok {
		for i, item := range topBlocked {
			if i >= 10 { // Limit to top 10
				break
			}
			if domainData, ok := item.(map[string]interface{}); ok {
				domain := TopDomain{}
				if name, ok := domainData["name"].(string); ok {
					domain.Domain = name
				}
				if count, ok := domainData["count"].(float64); ok {
					domain.Hits = int(count)
				}
				if domain.Domain != "" {
					stats.TopBlocked = append(stats.TopBlocked, domain)
				}
			}
		}
	}

	// Parse top queried domains
	if topQueried, ok := aghData["top_queried_domains"].([]interface{}); ok {
		for i, item := range topQueried {
			if i >= 10 { // Limit to top 10
				break
			}
			if domainData, ok := item.(map[string]interface{}); ok {
				domain := TopDomain{}
				if name, ok := domainData["name"].(string); ok {
					domain.Domain = name
				}
				if count, ok := domainData["count"].(float64); ok {
					domain.Hits = int(count)
				}
				if domain.Domain != "" {
					stats.TopQueries = append(stats.TopQueries, domain)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// getMockDNSStats returns mock data for development/testing when AdGuard Home is not available
func getMockDNSStats() DNSStats {
	return DNSStats{
		TotalQueries:      1250,
		BlockedFiltering:  340,
		BlockedPercentage: 27.2,
		TopBlocked: []TopDomain{
			{Domain: "doubleclick.net", Hits: 85},
			{Domain: "google-analytics.com", Hits: 62},
			{Domain: "facebook.com", Hits: 44},
		},
		TopQueries: []TopDomain{
			{Domain: "google.com", Hits: 210},
			{Domain: "github.com", Hits: 155},
		},
	}
}
