package main

import (
	"net"
	"testing"
)

func TestIsValidDHCPRange(t *testing.T) {
	_, subnet24, _ := net.ParseCIDR("192.168.1.0/24")
	routerIP := net.ParseIP("192.168.1.1")

	tests := []struct {
		name       string
		startIPStr string
		endIPStr   string
		routerIP   net.IP
		subnet     *net.IPNet
		wantErr    bool
	}{
		{
			name:       "Valid range",
			startIPStr: "192.168.1.100",
			endIPStr:   "192.168.1.200",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    false,
		},
		{
			name:       "Range includes router IP at start",
			startIPStr: "192.168.1.1",
			endIPStr:   "192.168.1.100",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Range includes router IP in middle",
			startIPStr: "192.168.1.1",
			endIPStr:   "192.168.1.3",
			routerIP:   net.ParseIP("192.168.1.2"),
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Range includes router IP at end",
			startIPStr: "192.168.1.100",
			endIPStr:   "192.168.1.254",
			routerIP:   net.ParseIP("192.168.1.254"),
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Start IP > End IP",
			startIPStr: "192.168.1.200",
			endIPStr:   "192.168.1.100",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Includes Network Address",
			startIPStr: "192.168.1.0",
			endIPStr:   "192.168.1.100",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Includes Broadcast Address",
			startIPStr: "192.168.1.200",
			endIPStr:   "192.168.1.255",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Start outside subnet",
			startIPStr: "192.168.2.100",
			endIPStr:   "192.168.1.200",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "End outside subnet",
			startIPStr: "192.168.1.100",
			endIPStr:   "192.168.2.200",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
		{
			name:       "Invalid IP format",
			startIPStr: "not-an-ip",
			endIPStr:   "192.168.1.200",
			routerIP:   routerIP,
			subnet:     subnet24,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidDHCPRange(tt.startIPStr, tt.endIPStr, tt.routerIP, tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Errorf("isValidDHCPRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIpToUint32(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want uint32
	}{
		{"Min", "0.0.0.0", 0},
		{"Max", "255.255.255.255", 4294967295},
		{"Localhost", "127.0.0.1", 2130706433},
		{"Private", "192.168.1.1", 3232235777},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := ipToUint32(ip); got != tt.want {
				t.Errorf("ipToUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}
