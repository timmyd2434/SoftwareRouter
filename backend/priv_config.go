package main

import (
	"log"
	"os"
)

// Files that root-run software interprets (service configs, firewall rules, VPN configs) must not
// be writable by the unprivileged backend, because content such as a WireGuard PostUp line or a
// dnsmasq dhcp-script directive would run as root. They are written through writeRootConfig:
//
//   - While the backend still runs as root it writes the file itself, exactly as before, and checks
//     the content against the privileged helper's path and content policy ("shadow mode"). Any
//     disagreement is logged as [PRIVHELPER-SHADOW], so mismatches are found while nothing can break.
//   - Once the backend runs without root, the same call sends the write to the helper, which
//     enforces that policy.

// shadowCheckManagedWrite logs when the helper would refuse a write. It never changes behaviour.
func shadowCheckManagedWrite(path string, content []byte) {
	if err := validateManagedPath(path, false); err != nil {
		log.Printf("[PRIVHELPER-SHADOW] the helper would refuse to write %s: %v", path, err)
		return
	}
	if err := validateManagedContent(path, content); err != nil {
		log.Printf("[PRIVHELPER-SHADOW] the helper would refuse this content for %s: %v", path, err)
	}
}

// writeRootConfig writes a root-interpreted config file (not atomic, like os.WriteFile).
func writeRootConfig(path string, content []byte, mode os.FileMode) error {
	if isRoot() {
		shadowCheckManagedWrite(path, content)
		return os.WriteFile(path, content, mode)
	}
	return writeManagedFile(path, content, mode)
}

// writeRootConfigAtomic is writeRootConfig for files that must never be seen half-written
// (wg0.conf is read by wg-quick at any moment).
func writeRootConfigAtomic(path string, content []byte, mode os.FileMode) error {
	if isRoot() {
		shadowCheckManagedWrite(path, content)
		return writeFileAtomic(path, content, mode)
	}
	return writeManagedFile(path, content, mode)
}

// defaultWGConfPath is where the WireGuard server config really lives.
const defaultWGConfPath = "/etc/wireguard/wg0.conf"

// readWireGuardConf reads wg0.conf. The file is root-owned, so without root it is read through
// the helper. Tests point wgConfPath at a temporary file, which is read directly.
func readWireGuardConf() ([]byte, error) {
	if wgConfPath != defaultWGConfPath {
		return os.ReadFile(wgConfPath)
	}
	return readManagedFile(wgConfPath)
}
