package main

import (
	"net"
	"testing"
)

func TestCheckReservedAddresses(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"IPv4 zero", "0.0.0.0", true},
		{"IPv4 broadcast", "255.255.255.255", true},
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback high", "127.255.255.255", true},
		{"IPv6 unspecified", "::", true},
		{"IPv6 loopback", "::1", true},
		{"Valid private IPv4", "192.168.1.1", false},
		{"Valid private IPv4 10", "10.0.0.1", false},
		{"Valid public IPv4", "8.8.8.8", false},
		{"Valid IPv6", "2001:db8::1", false},
		{"Valid link-local IPv6", "fe80::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse test IP: %s", tt.ip)
			}
			err := checkReservedAddresses(ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkReservedAddresses(%s) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestSubnetsOverlap(t *testing.T) {
	tests := []struct {
		name    string
		cidrA   string
		cidrB   string
		overlap bool
	}{
		{
			name:    "Identical subnets",
			cidrA:   "192.168.1.0/24",
			cidrB:   "192.168.1.0/24",
			overlap: true,
		},
		{
			name:    "Supernet contains subnet",
			cidrA:   "10.0.0.0/8",
			cidrB:   "10.0.1.0/24",
			overlap: true,
		},
		{
			name:    "Subnet contained in supernet",
			cidrA:   "10.0.1.0/24",
			cidrB:   "10.0.0.0/8",
			overlap: true,
		},
		{
			name:    "Same prefix different subnets",
			cidrA:   "192.168.1.0/24",
			cidrB:   "192.168.2.0/24",
			overlap: false,
		},
		{
			name:    "Completely different subnets",
			cidrA:   "10.0.0.0/24",
			cidrB:   "172.16.0.0/24",
			overlap: false,
		},
		{
			name:    "Adjacent subnets no overlap",
			cidrA:   "192.168.0.0/25",
			cidrB:   "192.168.0.128/25",
			overlap: false,
		},
		{
			name:    "Half overlap via supernet",
			cidrA:   "192.168.0.0/24",
			cidrB:   "192.168.0.0/25",
			overlap: true,
		},
		{
			name:    "IPv6 identical",
			cidrA:   "2001:db8::/32",
			cidrB:   "2001:db8::/32",
			overlap: true,
		},
		{
			name:    "IPv6 no overlap",
			cidrA:   "2001:db8:1::/48",
			cidrB:   "2001:db8:2::/48",
			overlap: false,
		},
		{
			name:    "IPv4 vs IPv6 no overlap",
			cidrA:   "192.168.1.0/24",
			cidrB:   "2001:db8::/32",
			overlap: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, netA, err := net.ParseCIDR(tt.cidrA)
			if err != nil {
				t.Fatalf("Failed to parse CIDR A: %s", tt.cidrA)
			}
			_, netB, err := net.ParseCIDR(tt.cidrB)
			if err != nil {
				t.Fatalf("Failed to parse CIDR B: %s", tt.cidrB)
			}

			got := subnetsOverlap(netA, netB)
			if got != tt.overlap {
				t.Errorf("subnetsOverlap(%s, %s) = %v, want %v", tt.cidrA, tt.cidrB, got, tt.overlap)
			}

			// Overlap should be symmetric
			gotReverse := subnetsOverlap(netB, netA)
			if gotReverse != tt.overlap {
				t.Errorf("subnetsOverlap(%s, %s) [reversed] = %v, want %v", tt.cidrB, tt.cidrA, gotReverse, tt.overlap)
			}
		})
	}
}

func TestCheckIPConflicts_ReservedAddresses(t *testing.T) {
	// These should fail regardless of system state
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"Zero address", "0.0.0.0/32", true},
		{"Broadcast", "255.255.255.255/32", true},
		{"Loopback", "127.0.0.1/8", true},
		{"IPv6 unspecified", "::/128", true},
		{"IPv6 loopback", "::1/128", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkIPConflicts(tt.ip, "testif0", "add")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkIPConflicts(%s) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestCheckIPConflicts_SkipsOnDelete(t *testing.T) {
	// Delete actions should never be blocked, even for reserved addresses
	err := checkIPConflicts("0.0.0.0/32", "testif0", "del")
	if err != nil {
		t.Errorf("checkIPConflicts with action 'del' should not return error, got: %v", err)
	}
}

func TestCheckIPConflicts_InvalidFormat(t *testing.T) {
	err := checkIPConflicts("not-an-ip", "testif0", "add")
	if err == nil {
		t.Error("Expected error for invalid IP format, got nil")
	}
}
