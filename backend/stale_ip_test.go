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
