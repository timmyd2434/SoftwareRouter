package main

import (
	"strings"
	"testing"
)

func TestBuildFRRConfigString(t *testing.T) {
	config := DynamicRoutingConfig{
		OSPF: OSPFConfig{
			Enabled:      true,
			RouterID:     "1.1.1.1",
			Redistribute: []string{"connected", "static"},
			Networks: []OSPFNet{
				{Network: "10.0.0.0/24", Area: "0"},
			},
		},
		BGP: BGPConfig{
			Enabled:  true,
			ASN:      65001,
			RouterID: "1.1.1.1",
			Neighbors: []BGPNeighbor{
				{IP: "192.168.1.2", RemoteASN: 65002},
			},
			Networks: []string{"10.0.0.0/8"},
		},
	}

	output := buildFRRConfigString(config)

	// Verify key components
	expectedSubstrings := []string{
		"router ospf",
		"ospf router-id 1.1.1.1",
		"network 10.0.0.0/24 area 0",
		"redistribute connected",
		"redistribute static",
		"router bgp 65001",
		"bgp router-id 1.1.1.1",
		"neighbor 192.168.1.2 remote-as 65002",
		"address-family ipv4 unicast",
		"network 10.0.0.0/8",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(output, s) {
			t.Errorf("Expected config to contain '%s', but it didn't.\nGenerated Config:\n%s", s, output)
		}
	}
}

func TestBuildFRRConfigString_Disabled(t *testing.T) {
	config := DynamicRoutingConfig{
		OSPF: OSPFConfig{Enabled: false},
		BGP:  BGPConfig{Enabled: false},
	}

	output := buildFRRConfigString(config)

	if strings.Contains(output, "router ospf") {
		t.Error("Did not expect OSPF config when disabled")
	}
	if strings.Contains(output, "router bgp") {
		t.Error("Did not expect BGP config when disabled")
	}
}
