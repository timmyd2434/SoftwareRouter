package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTopDomains_AdGuardStandard(t *testing.T) {
	// Standard AdGuard Home format: array of single-key maps
	raw := []interface{}{
		map[string]interface{}{"doubleclick.net": float64(85)},
		map[string]interface{}{"google-analytics.com": float64(62)},
	}

	res := parseTopDomains(raw)
	if len(res) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(res))
	}
	if res[0].Domain != "doubleclick.net" || res[0].Hits != 85 {
		t.Errorf("unexpected domain 0: %+v", res[0])
	}
	if res[1].Domain != "google-analytics.com" || res[1].Hits != 62 {
		t.Errorf("unexpected domain 1: %+v", res[1])
	}
}

func TestParseTopDomains_ExplicitKeys(t *testing.T) {
	// Explicit name/count objects
	raw := []interface{}{
		map[string]interface{}{"name": "doubleclick.net", "count": float64(85)},
		map[string]interface{}{"domain": "google-analytics.com", "hits": float64(62)},
	}

	res := parseTopDomains(raw)
	if len(res) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(res))
	}
	if res[0].Domain != "doubleclick.net" || res[0].Hits != 85 {
		t.Errorf("unexpected domain 0: %+v", res[0])
	}
	if res[1].Domain != "google-analytics.com" || res[1].Hits != 62 {
		t.Errorf("unexpected domain 1: %+v", res[1])
	}
}

func TestParseTopDomains_DirectMap(t *testing.T) {
	// Direct map format
	raw := map[string]interface{}{
		"doubleclick.net": float64(85),
	}

	res := parseTopDomains(raw)
	if len(res) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(res))
	}
	if res[0].Domain != "doubleclick.net" || res[0].Hits != 85 {
		t.Errorf("unexpected domain 0: %+v", res[0])
	}
}

func TestParseTopDomains_NilOrEmpty(t *testing.T) {
	res := parseTopDomains(nil)
	if res == nil || len(res) != 0 {
		t.Fatalf("expected empty slice, got %+v", res)
	}
}

func TestGetDNSStats_MockFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/dns/stats", nil)
	w := httptest.NewRecorder()

	getDNSStats(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var stats DNSStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if stats.TotalQueries == 0 {
		t.Errorf("expected non-zero total queries in fallback stats")
	}
	if len(stats.TopBlocked) == 0 {
		t.Errorf("expected top blocked domains in fallback stats")
	}
}
