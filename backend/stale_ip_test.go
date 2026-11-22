package main

import (
	"strings"
	"testing"
)

func TestFilterStaleIPsDropsOnlyDeletedVLANs(t *testing.T) {
	exists := map[string]bool{"eno1.20": true, "eno1.30": true, "br0": true, "enp3s0f2": true}
	persisted := map[string]bool{"eno1.40": true}
	ips := []SavedIP{
		{InterfaceName: "br0", IPAddress: "192.168.3.1/24"},
		{InterfaceName: "enp3s0f2", IPAddress: "192.168.4.1/24"},
		{InterfaceName: "eno1.20", IPAddress: "192.168.20.1/24"},
		{InterfaceName: "eno1.30", IPAddress: "192.168.30.1/24"},
		{InterfaceName: "eno1.40", IPAddress: "192.168.40.1/24"}, // saved VLAN, not up yet: keep
		{InterfaceName: "eno1.2", IPAddress: "192.168.20.1/24"},  // deleted VLAN: stale
		{InterfaceName: "eno1.3", IPAddress: "192.168.30.1/24"},
		{InterfaceName: "eno1.25", IPAddress: "192.168.25.1/24"},
	}
	kept, stale := filterStaleIPs(ips,
		func(n string) bool { return exists[n] },
		func(n string) bool { return persisted[n] })

	if strings.Join(stale, ",") != "eno1.2,eno1.25,eno1.3" {
		t.Errorf("stale = %v", stale)
	}
	var names []string
	for _, ip := range kept {
		names = append(names, ip.InterfaceName)
	}
	if strings.Join(names, ",") != "br0,enp3s0f2,eno1.20,eno1.30,eno1.40" {
		t.Errorf("kept = %v", names)
	}
}

func TestRemovePersistedIPsForOnlyTouchesThatInterface(t *testing.T) {
	interfacesStoreLock.Lock()
	old := interfacesStore.IPs
	interfacesStore.IPs = []SavedIP{
		{InterfaceName: "eno1.20", IPAddress: "192.168.20.1/24"},
		{InterfaceName: "eno1.2", IPAddress: "192.168.20.1/24"},
		{InterfaceName: "eno1.2", IPAddress: "10.9.9.1/24"},
	}
	interfacesStoreLock.Unlock()
	defer func() { interfacesStoreLock.Lock(); interfacesStore.IPs = old; interfacesStoreLock.Unlock() }()

	// Nothing to remove for an unknown interface, so no file is written.
	removePersistedIPsFor("nope")
	interfacesStoreLock.RLock()
	n := len(interfacesStore.IPs)
	interfacesStoreLock.RUnlock()
	if n != 3 {
		t.Errorf("unknown interface must not change the list, have %d entries", n)
	}
}

func TestFilterStaleIPsCoversBridgesAndBonds(t *testing.T) {
	ips := []SavedIP{
		{InterfaceName: "br0", IPAddress: "192.168.3.1/24"},
		{InterfaceName: "br1", IPAddress: "192.168.7.1/24"},   // deleted bridge
		{InterfaceName: "bond1", IPAddress: "192.168.8.1/24"}, // deleted bond
		{InterfaceName: "br2", IPAddress: "192.168.9.1/24"},   // saved, not up yet
		{InterfaceName: "enp9s0f9", IPAddress: "10.0.0.1/24"}, // physical NIC
	}
	kept, stale := filterStaleIPs(ips,
		func(n string) bool { return n == "br0" },
		func(n string) bool { return n == "br2" })
	if strings.Join(stale, ",") != "bond1,br1" || len(kept) != 3 {
		t.Errorf("stale=%v kept=%d", stale, len(kept))
	}
}

func TestVirtualInterfaceNames(t *testing.T) {
	for _, yes := range []string{"eno1.20", "enp3s0f0.30", "br0", "br12", "bond0"} {
		if !isVirtualInterfaceName(yes) {
			t.Errorf("%q should count as virtual", yes)
		}
	}
	for _, no := range []string{"eno1", "enp3s0f1", "wg0", "lo", "br-lan", "bridge", "bond", "docker0"} {
		if isVirtualInterfaceName(no) {
			t.Errorf("%q must not count as virtual", no)
		}
	}
}
