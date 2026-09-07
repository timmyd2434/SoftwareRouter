package main

import (
	"strings"
	"testing"
)

func TestGeoBlockingDisabledRules(t *testing.T) {
	cfgDisabled := &GeoBlockingConfig{
		Enabled:          false,
		Mode:             "blocklist",
		BlockedCountries: []string{"CN", "RU"},
	}

	rules := generateGeoBlockingRules(cfgDisabled)
	if rules != "" {
		t.Errorf("Expected empty rules string when GeoBlocking is disabled, got %q", rules)
	}

	defines, err := generateGeoBlockingDefines(cfgDisabled)
	if err != nil {
		t.Fatalf("Unexpected error generating defines: %v", err)
	}
	if defines != "" {
		t.Errorf("Expected empty defines string when GeoBlocking is disabled, got %q", defines)
	}
}

func TestGeoBlockingEnabledRules(t *testing.T) {
	cfgEnabled := &GeoBlockingConfig{
		Enabled:          true,
		Mode:             "blocklist",
		BlockedCountries: []string{},
	}

	rules := generateGeoBlockingRules(cfgEnabled)
	if rules != "" {
		t.Errorf("Expected empty rules string when no countries blocked, got %q", rules)
	}

	cfgEnabled.BlockedCountries = []string{"XX"}
	// Test rules generation string output structure
	rules = generateGeoBlockingRules(cfgEnabled)
	if rules == "" || !strings.Contains(rules, "GeoBlocking Rules") {
		t.Errorf("Expected GeoBlocking rules string when enabled, got %q", rules)
	}
}
