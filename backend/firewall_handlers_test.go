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

func TestNormaliseRuleIgnoresComments(t *testing.T) {
	ruleWithComment1 := `iifname "lo" accept comment "-"`
	ruleWithComment2 := `iifname "lo" accept comment "loop back rule"`
	ruleWithoutComment := `iifname "lo" accept`

	norm1 := normaliseRule(ruleWithComment1)
	norm2 := normaliseRule(ruleWithComment2)
	norm3 := normaliseRule(ruleWithoutComment)

	if norm1 != norm2 {
		t.Errorf("Expected norm1 (%s) to equal norm2 (%s)", norm1, norm2)
	}
	if norm1 != norm3 {
		t.Errorf("Expected norm1 (%s) to equal norm3 (%s)", norm1, norm3)
	}
}

func TestCleanExprListStripsComments(t *testing.T) {
	sampleJSON := `[
		{
			"match": {
				"op": "==",
				"left": { "meta": { "key": "iifname" } },
				"right": "lo"
			}
		},
		{ "accept": null },
		{ "comment": "loop back rule" }
	]`

	var exprList []interface{}
	if err := json.Unmarshal([]byte(sampleJSON), &exprList); err != nil {
		t.Fatalf("Failed to unmarshal sample JSON: %v", err)
	}

	cleaned := cleanExprList(exprList)
	if len(cleaned) != 2 {
		t.Errorf("Expected 2 items after cleaning comments, got %d", len(cleaned))
	}

	for _, item := range cleaned {
		if m, ok := item.(map[string]interface{}); ok {
			if _, hasComment := m["comment"]; hasComment {
				t.Errorf("Cleaned exprList still contains comment: %v", item)
			}
		}
	}
}
