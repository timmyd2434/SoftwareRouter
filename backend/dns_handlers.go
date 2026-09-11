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

func parseTopDomains(raw interface{}) []TopDomain {
	result := make([]TopDomain, 0)
	if raw == nil {
		return result
	}

	addDomain := func(d string, h int) {
		if d == "" {
			return
		}
		for _, existing := range result {
			if existing.Domain == d {
				return
			}
		}
		result = append(result, TopDomain{Domain: d, Hits: h})
	}

	// Format 1: Array of items (AdGuard Home: [{"domain.com": 85}] or [{"name": "domain.com", "count": 85}])
	if list, ok := raw.([]interface{}); ok {
		for _, item := range list {
			if len(result) >= 10 {
				break
			}
			if obj, ok := item.(map[string]interface{}); ok {
				var domainName string
				var hitsCount int
				foundExplicit := false

				// Check explicit keys: "name", "domain", "host"
				for _, key := range []string{"name", "domain", "host"} {
					if v, ok := obj[key].(string); ok && v != "" {
						domainName = v
						foundExplicit = true
						break
					}
				}
				// Check explicit count keys: "count", "hits", "value", "queries"
				for _, key := range []string{"count", "hits", "value", "queries"} {
					if v, ok := obj[key].(float64); ok {
						hitsCount = int(v)
						break
					}
				}

				if foundExplicit && domainName != "" {
					addDomain(domainName, hitsCount)
					continue
				}

				// Single-key map format: {"doubleclick.net": 85}
				for k, v := range obj {
					if countFloat, ok := v.(float64); ok {
						addDomain(k, int(countFloat))
						break
					}
				}
			}
		}
		return result
	}

	// Format 2: Map/Object (Pi-hole: {"doubleclick.net": 85, "google-analytics.com": 62})
	if obj, ok := raw.(map[string]interface{}); ok {
		for k, v := range obj {
			if len(result) >= 10 {
				break
			}
			if countFloat, ok := v.(float64); ok {
				addDomain(k, int(countFloat))
			}
		}
	}

	return result
}

func getDNSStats(w http.ResponseWriter, r *http.Request) {
	stats := DNSStats{
		TopBlocked: make([]TopDomain, 0),
		TopQueries: make([]TopDomain, 0),
		TopClients: make([]TopDomain, 0),
	}

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

	// Parse top blocked domains, queried domains, and clients using multi-format parser
	stats.TopBlocked = parseTopDomains(aghData["top_blocked_domains"])
	stats.TopQueries = parseTopDomains(aghData["top_queried_domains"])
	stats.TopClients = parseTopDomains(aghData["top_clients"])

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
		TopClients: []TopDomain{
			{Domain: "192.168.1.100", Hits: 850},
		},
	}
}
