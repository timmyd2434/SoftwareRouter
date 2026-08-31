package main

import (
	"encoding/json"
	"testing"
)

func TestExtractReferencedInterfaces(t *testing.T) {
	// Sample JSON expression structure as returned by nft -j list ruleset
	sampleJSON := `[
		{
			"match": {
				"op": "==",
				"left": {
					"meta": {
						"key": "iifname"
					}
				},
				"right": "br1"
			}
		},
		{
			"match": {
				"op": "==",
				"left": {
					"meta": {
						"key": "oifname"
					}
				},
				"right": "eth0"
			}
		},
		{
			"accept": null
		}
	]`

	var exprList []interface{}
	if err := json.Unmarshal([]byte(sampleJSON), &exprList); err != nil {
		t.Fatalf("Failed to unmarshal sample JSON: %v", err)
	}

	ifaces := extractReferencedInterfaces(exprList)
	if len(ifaces) != 2 {
		t.Errorf("Expected 2 interfaces, got %d (%v)", len(ifaces), ifaces)
	}

	hasBr1 := false
	hasEth0 := false
	for _, name := range ifaces {
		if name == "br1" {
			hasBr1 = true
		}
		if name == "eth0" {
			hasEth0 = true
		}
	}

	if !hasBr1 || !hasEth0 {
		t.Errorf("Expected br1 and eth0 to be extracted, got %v", ifaces)
	}
}
