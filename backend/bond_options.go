package main

import "fmt"

// bondOptions are the bonding parameters SoftRouter sets, with the values it accepts.
// A nil value check means "any integer in range", validated by the caller.
var bondOptions = map[string]func(string) bool{
	"miimon": func(v string) bool {
		var n int
		_, err := fmt.Sscanf(v, "%d", &n)
		return err == nil && fmt.Sprint(n) == v && n >= 0 && n <= 10000
	},
	"lacp_rate":        func(v string) bool { return v == "slow" || v == "fast" },
	"xmit_hash_policy": func(v string) bool { return v == "layer2" || v == "layer2+3" || v == "layer3+4" },
}

// setBondOption sets one bonding parameter with "ip link set dev <bond> type bond <option> <value>".
// It has the same effect as writing /sys/class/net/<bond>/bonding/<option> (both end up in the
// kernel's bonding option handler), but goes through the privileged command path, so the backend
// needs no write access to sysfs.
func setBondOption(bond, option, value string) error {
	if !isValidInterfaceName(bond) {
		return fmt.Errorf("invalid bond name %q", bond)
	}
	check, ok := bondOptions[option]
	if !ok {
		return fmt.Errorf("bonding option %q is not allowed", option)
	}
	if !check(value) {
		return fmt.Errorf("invalid value %q for bonding option %s", value, option)
	}
	_, err := runPrivilegedCombinedOutput("ip", "link", "set", "dev", bond, "type", "bond", option, value)
	return err
}
