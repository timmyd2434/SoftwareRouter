package main

import (
	"os"
	"strings"
)

const firstBootFlagFile = "/etc/softrouter/first_boot_complete"

// isFirstBoot checks if this is the first time the system is booting
func isFirstBoot() bool {
	_, err := os.Stat(firstBootFlagFile)
	return os.IsNotExist(err)
}

// markFirstBootComplete creates the flag file to indicate first boot is done
func markFirstBootComplete() error {
	// Ensure directory exists
	if err := os.MkdirAll("/etc/softrouter", 0755); err != nil {
		return err
	}
	return os.WriteFile(firstBootFlagFile, []byte("1"), 0644)
}

// needsWANConfiguration checks if any interface is explicitly labeled as WAN
// Returns true if no WAN interfaces are configured (requires setup)
func needsWANConfiguration() bool {
	metaStore, err := loadInterfaceMetadata()
	if err != nil {
		return true // If we can't load metadata, assume setup needed
	}

	// Check if any interface has WAN label
	for _, meta := range metaStore.Metadata {
		if strings.EqualFold(meta.Label, "WAN") {
			return false
		}
	}

	return true
}
