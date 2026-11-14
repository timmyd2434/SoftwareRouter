package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// sanitizeNFTValue rejects any string that could break out of a quoted nftables
// token or inject extra rules/statements. It is deliberately strict: anything
// interpolated into a generated ruleset (interface names, MACs, ports, comments)
// must pass through this helper first.
func sanitizeNFTValue(s string) error {
	if s == "" {
		return fmt.Errorf("empty value")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("control character in value")
		}
		switch r {
		case '"', '\'', '\\', '{', '}', ';', '#', '`', '$', '\n', '\r':
			return fmt.Errorf("illegal character %q in value", r)
		}
	}
	return nil
}

// containsControlChars reports whether s has any control character (incl. CR/LF).
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateInterfaceLabel validates the free-form label stored in interface
// metadata (e.g. "WAN", "LAN", "Bridge", or a user label).
func validateInterfaceLabel(label string) error {
	if len(label) > 32 {
		return fmt.Errorf("label too long")
	}
	if containsControlChars(label) {
		return fmt.Errorf("label contains control characters")
	}
	if strings.ContainsAny(label, "\"\\{};#`$") {
		return fmt.Errorf("label contains illegal characters")
	}
	return nil
}

// validateMAC parses and normalises a MAC address (lower-case, colon separated).
func validateMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("invalid MAC address")
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("only 48-bit MAC addresses are supported")
	}
	return hw.String(), nil
}

// validatePortString validates a TCP/UDP port expressed as ":443" or "443".
func validatePortString(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(s), ":"))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

// validateHostOrIP accepts an IP literal or an RFC 1123 hostname.
func validateHostOrIP(h string) error {
	if h == "" || len(h) > 253 {
		return fmt.Errorf("invalid host")
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid hostname")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid hostname")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("invalid hostname")
			}
		}
	}
	return nil
}

var (
	leaseTimeRe = regexp.MustCompile(`^[0-9]{1,5}[smhd]$|^infinite$`)
	hostnameRe  = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
)

// validateDHCPConfigFields validates every field that is written into the
// generated dnsmasq config. Gateway and every address are validated
// unconditionally (not only when a range is populated).
func validateDHCPConfigFields(iface string, c DHCPConfig) error {
	if !isValidInterfaceName(iface) {
		return fmt.Errorf("invalid interface name")
	}
	v4 := func(label, v string, required bool) error {
		if v == "" {
			if required {
				return fmt.Errorf("%s is required", label)
			}
			return nil
		}
		if containsControlChars(v) || strings.ContainsAny(v, " ,;#\"'\\") {
			return fmt.Errorf("%s contains illegal characters", label)
		}
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("%s is not a valid IPv4 address", label)
		}
		return nil
	}
	if err := v4("gateway", c.Gateway, false); err != nil {
		return err
	}
	if err := v4("startIP", c.StartIP, c.Enabled); err != nil {
		return err
	}
	if err := v4("endIP", c.EndIP, c.Enabled); err != nil {
		return err
	}
	if c.LeaseTime != "" && !leaseTimeRe.MatchString(c.LeaseTime) {
		return fmt.Errorf("invalid lease time")
	}
	for _, d := range c.DNSServers {
		if err := v4("DNS server", d, true); err != nil {
			return err
		}
	}
	v6 := func(label, v string) error {
		if v == "" {
			return nil
		}
		if containsControlChars(v) || strings.ContainsAny(v, " ,;#\"'\\") {
			return fmt.Errorf("%s contains illegal characters", label)
		}
		ip := net.ParseIP(v)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("%s is not a valid IPv6 address", label)
		}
		return nil
	}
	if c.EnabledIPv6 {
		if c.StartIPv6 == "" || c.EndIPv6 == "" {
			return fmt.Errorf("IPv6 range is required when DHCPv6 is enabled")
		}
	}
	if err := v6("startIPv6", c.StartIPv6); err != nil {
		return err
	}
	if err := v6("endIPv6", c.EndIPv6); err != nil {
		return err
	}
	if c.LeaseTimeIPv6 != "" && !leaseTimeRe.MatchString(c.LeaseTimeIPv6) {
		return fmt.Errorf("invalid IPv6 lease time")
	}
	for _, d := range c.DNSServersIPv6 {
		if d == "" {
			return fmt.Errorf("empty IPv6 DNS server")
		}
		if err := v6("IPv6 DNS server", d); err != nil {
			return err
		}
	}
	return nil
}

// validateStaticLease validates a dhcp-host reservation.
func validateStaticLease(l StaticLease) error {
	if _, err := validateMAC(l.MAC); err != nil {
		return err
	}
	ip := net.ParseIP(l.IP)
	if ip == nil || ip.To4() == nil || containsControlChars(l.IP) {
		return fmt.Errorf("invalid static lease IP")
	}
	if l.Hostname != "" && !hostnameRe.MatchString(l.Hostname) {
		return fmt.Errorf("invalid static lease hostname")
	}
	return nil
}

// validateRAConfig validates a Router Advertisement config (prefix must be a
// well-formed IPv6 /64; DNS servers must be IPv6 literals).
func validateRAConfig(iface, prefix string, dns []string) error {
	if !isValidInterfaceName(iface) {
		return fmt.Errorf("invalid interface name")
	}
	if prefix != "" {
		if containsControlChars(prefix) || strings.ContainsAny(prefix, " ;{}#\"'\\") {
			return fmt.Errorf("prefix contains illegal characters")
		}
		ip, n, err := net.ParseCIDR(prefix)
		if err != nil || ip.To4() != nil {
			return fmt.Errorf("prefix must be an IPv6 CIDR")
		}
		if ones, _ := n.Mask.Size(); ones != 64 {
			return fmt.Errorf("prefix must be a /64")
		}
	}
	if len(dns) > 3 {
		return fmt.Errorf("at most 3 DNS servers")
	}
	for _, d := range dns {
		if containsControlChars(d) || strings.ContainsAny(d, " ;{}#\"'\\") {
			return fmt.Errorf("DNS server contains illegal characters")
		}
		ip := net.ParseIP(d)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("DNS server %q is not an IPv6 address", d)
		}
	}
	return nil
}
