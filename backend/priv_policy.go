package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Per-command argument policy for the privileged executor.
//
// allowedCommands only says WHICH binaries may run. Several of them are
// root-equivalent if their arguments are unconstrained (systemd-run, cp, curl,
// tail, journalctl, mkdir, openvpn, "ip netns exec", ...). Every command below
// therefore has a policy that accepts only the argument shapes SoftRouter
// actually uses. Anything else is refused before sudo is ever invoked.
//
// A command with no policy entry is refused outright: adding a binary to
// allowedCommands without writing its policy fails closed.

type argPolicy func(args []string) error

var commandPolicies map[string]argPolicy

func init() {
	commandPolicies = map[string]argPolicy{
		"nft":             policyNft,
		"ip":              policyDenyTokens("netns", "exec", "vrf", "xdp", "-b", "-batch", "-force"),
		"tc":              policyDenyTokens("exec", "-b", "-batch", "-force"),
		"systemctl":       policySystemctl,
		"sysctl":          policySysctl,
		"modprobe":        policyModprobe,
		"wg":              policyWg,
		"cloudflared":     policyCloudflared,
		"ping":            policyPing,
		"traceroute":      policyTraceroute,
		"journalctl":      policyJournalctl,
		"curl":            policyCurl,
		"pihole":          policyPihole,
		"cscli":           policyExact([]string{"decisions", "list", "-o", "json"}),
		"tail":            policyTail,
		"./easyrsa":       policyEasyRSA,
		"openvpn":         policyOpenVPN,
		"cp":              policyCp,
		"speedtest-cli":   policyExact([]string{"--json", "--secure"}),
		"uptime":          policyExact([]string{"-p"}),
		"mkdir":           policyMkdir,
		"suricata-update": policyExact([]string{"--no-merge"}),
		"ss":              policyExact([]string{"-tunap"}),
		"netstat":         policyExact([]string{"-tunap"}),
		"dnsmasq":         policyDnsmasq,
		"radvd":           policyRadvd,
		"conntrack":       policyConntrack,
		"update.sh":       policyUpdateScript,
		"./update.sh":     policyUpdateScript,
		"systemd-run":     policySystemdRun,
	}
}

// ---------------------------------------------------------------- helpers

var (
	safeUnitRe = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)
	ifaceRe    = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,32}$`)
)

func policyExact(want []string) argPolicy {
	return func(args []string) error {
		if len(args) != len(want) {
			return fmt.Errorf("unexpected arguments")
		}
		for i := range want {
			if args[i] != want[i] {
				return fmt.Errorf("unexpected argument %q", args[i])
			}
		}
		return nil
	}
}

func policyDenyTokens(deny ...string) argPolicy {
	set := map[string]bool{}
	for _, d := range deny {
		set[d] = true
	}
	return func(args []string) error {
		for _, a := range args {
			if set[a] {
				return fmt.Errorf("argument %q is not permitted", a)
			}
		}
		return nil
	}
}

// pathUnder reports whether p is an absolute, clean path inside one of dirs.
func pathUnder(p string, dirs ...string) bool {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return false
	}
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

func tmpDirs() []string {
	d := os.TempDir()
	if d == "" {
		d = "/tmp"
	}
	return []string{d, "/tmp"}
}

// ---------------------------------------------------------------- policies

func policyNft(args []string) error {
	i := 0
	sawFile := false
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		switch args[i] {
		case "-j", "-c", "-a", "-n", "-s":
			i++
		case "-f":
			if i+1 >= len(args) {
				return fmt.Errorf("nft -f needs a file")
			}
			if !pathUnder(args[i+1], append(tmpDirs(), "/etc/softrouter", "/etc/nftables.conf")...) {
				return fmt.Errorf("nft -f file outside permitted locations")
			}
			sawFile = true
			i += 2
		default:
			return fmt.Errorf("nft option %q is not permitted", args[i])
		}
	}
	if i >= len(args) {
		if sawFile {
			return nil // `nft [-c] -f file`
		}
		return fmt.Errorf("nft requires a command")
	}
	if sawFile {
		return fmt.Errorf("nft -f cannot be combined with a command")
	}
	switch args[i] {
	case "list", "add", "delete", "flush", "insert", "replace":
		return nil
	}
	return fmt.Errorf("nft command %q is not permitted", args[i])
}

var systemctlActions = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true,
	"reload-or-restart": true, "enable": true, "disable": true,
	"is-active": true, "show": true, "daemon-reload": true,
}

var systemctlUnits = map[string]bool{
	"dnsmasq": true, "unbound": true, "AdGuardHome": true, "adguardhome": true,
	"pihole-FTL": true, "suricata": true, "crowdsec": true, "unifi": true,
	"cloudflared": true, "openvpn": true, "miniupnpd": true, "frr": true,
	"radvd": true, "systemd-resolved": true,
}

var systemctlUnitPrefixes = []string{"wg-quick@", "openvpn-client@", "openvpn-server@"}

func systemctlUnitAllowed(u string) bool {
	u = strings.TrimSuffix(u, ".service")
	if !safeUnitRe.MatchString(u) {
		return false
	}
	if systemctlUnits[u] {
		return true
	}
	for _, p := range systemctlUnitPrefixes {
		if strings.HasPrefix(u, p) && len(u) > len(p) {
			return true
		}
	}
	return false
}

func policySystemctl(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("systemctl requires an action")
	}
	if !systemctlActions[args[0]] {
		return fmt.Errorf("systemctl action %q is not permitted", args[0])
	}
	if args[0] == "daemon-reload" {
		if len(args) != 1 {
			return fmt.Errorf("daemon-reload takes no arguments")
		}
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("systemctl %s requires a unit", args[0])
	}
	if !systemctlUnitAllowed(args[1]) {
		return fmt.Errorf("systemctl unit %q is not permitted", args[1])
	}
	for _, extra := range args[2:] {
		if extra != "--property=ActiveEnterTimestamp" && extra != "--no-pager" {
			return fmt.Errorf("systemctl option %q is not permitted", extra)
		}
	}
	return nil
}

var sysctlKeys = map[string]bool{
	"net.ipv4.ip_forward":                    true,
	"net.ipv4.conf.all.route_localnet":       true,
	"net.ipv4.conf.default.route_localnet":   true,
	"net.netfilter.nf_conntrack_acct":        true,
}

func policySysctl(args []string) error {
	if len(args) != 2 || args[0] != "-w" {
		return fmt.Errorf("only `sysctl -w key=value` is permitted")
	}
	k, v, ok := strings.Cut(args[1], "=")
	if !ok || !sysctlKeys[k] || (v != "0" && v != "1") {
		return fmt.Errorf("sysctl setting %q is not permitted", args[1])
	}
	return nil
}

func policyModprobe(args []string) error {
	if len(args) == 1 && (args[0] == "bonding" || args[0] == "nf_conntrack") {
		return nil
	}
	return fmt.Errorf("modprobe module is not permitted")
}

func policyWg(args []string) error {
	switch {
	case len(args) == 1 && (args[0] == "genkey" || args[0] == "pubkey" || args[0] == "show"):
		return nil
	case len(args) == 3 && args[0] == "syncconf" && ifaceRe.MatchString(args[1]) && pathUnder(args[2], "/etc/wireguard"):
		return nil
	}
	return fmt.Errorf("wg arguments are not permitted")
}

func policyCloudflared(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "--version":
		return nil
	case len(args) == 2 && args[0] == "service" && args[1] == "uninstall":
		return nil
	case len(args) == 3 && args[0] == "service" && args[1] == "install" && isValidCloudflareToken(args[2]):
		return nil
	}
	return fmt.Errorf("cloudflared arguments are not permitted")
}

func validDiagTarget(t string) bool {
	return t != "" && !strings.HasPrefix(t, "-") && validateHostOrIP(t) == nil
}

func policyPing(args []string) error {
	// ping [-I iface] -c N -W N target
	i := 0
	if len(args) >= 2 && args[0] == "-I" {
		if !ifaceRe.MatchString(args[1]) {
			return fmt.Errorf("invalid interface")
		}
		i = 2
	}
	rest := args[i:]
	if len(rest) != 5 || rest[0] != "-c" || rest[2] != "-W" {
		return fmt.Errorf("unexpected ping arguments")
	}
	if n, err := strconv.Atoi(rest[1]); err != nil || n < 1 || n > 10 {
		return fmt.Errorf("invalid ping count")
	}
	if n, err := strconv.Atoi(rest[3]); err != nil || n < 1 || n > 10 {
		return fmt.Errorf("invalid ping wait")
	}
	if !validDiagTarget(rest[4]) {
		return fmt.Errorf("invalid ping target")
	}
	return nil
}

func policyTraceroute(args []string) error {
	if len(args) != 5 || args[0] != "-w" || args[1] != "2" || args[2] != "-m" || args[3] != "15" {
		return fmt.Errorf("unexpected traceroute arguments")
	}
	if !validDiagTarget(args[4]) {
		return fmt.Errorf("invalid traceroute target")
	}
	return nil
}

func policyJournalctl(args []string) error {
	// journalctl -u softrouter -n N --no-pager
	if len(args) != 5 || args[0] != "-u" || args[1] != "softrouter" || args[2] != "-n" || args[4] != "--no-pager" {
		return fmt.Errorf("only the softrouter unit log may be read")
	}
	if n, err := strconv.Atoi(args[3]); err != nil || n < 1 || n > 5000 {
		return fmt.Errorf("invalid line count")
	}
	return nil
}

var curlFlagSet = map[string]bool{"-f": true, "-s": true, "-S": true, "-L": true, "-fsSL": true, "-sSL": true}

func policyCurl(args []string) error {
	var url, out string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case curlFlagSet[a]:
		case a == "-m" && i+1 < len(args):
			if n, err := strconv.Atoi(args[i+1]); err != nil || n < 1 || n > 300 {
				return fmt.Errorf("invalid curl timeout")
			}
			i++
		case a == "-o" && i+1 < len(args):
			out = args[i+1]
			i++
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("curl option %q is not permitted", a)
		default:
			if url != "" {
				return fmt.Errorf("only one URL is permitted")
			}
			url = a
		}
	}
	if url == "" {
		return fmt.Errorf("curl requires a URL")
	}
	// https only, with the single bare-host exception used for public-IP lookup
	if !strings.HasPrefix(url, "https://") && url != "ifconfig.me" {
		return fmt.Errorf("curl URL must be https://")
	}
	if out != "" && !pathUnder(out, "/etc/softrouter", "/tmp/cloudflare.gpg") && out != "/tmp/cloudflare.gpg" {
		return fmt.Errorf("curl output path is not permitted")
	}
	return nil
}

func policyPihole(args []string) error {
	if len(args) == 1 && (args[0] == "enable" || args[0] == "-v") {
		return nil
	}
	return fmt.Errorf("pihole arguments are not permitted")
}

func policyTail(args []string) error {
	// tail -n N /var/log/suricata/eve.json
	if len(args) != 3 || args[0] != "-n" || args[2] != "/var/log/suricata/eve.json" {
		return fmt.Errorf("only the Suricata eve log may be tailed")
	}
	if n, err := strconv.Atoi(args[1]); err != nil || n < 1 || n > 5000 {
		return fmt.Errorf("invalid line count")
	}
	return nil
}

func policyEasyRSA(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("easyrsa requires a command")
	}
	i := 0
	if args[0] == "--batch" {
		i = 1
	}
	rest := args[i:]
	if len(rest) == 0 {
		return fmt.Errorf("easyrsa requires a command")
	}
	for _, a := range rest {
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("easyrsa option %q is not permitted", a)
		}
	}
	switch rest[0] {
	case "init-pki", "gen-dh", "gen-crl":
		return nil
	case "build-ca":
		if len(rest) == 2 && rest[1] == "nopass" {
			return nil
		}
	case "build-server-full", "build-client-full":
		if len(rest) == 3 && safeUnitRe.MatchString(rest[1]) && rest[2] == "nopass" {
			return nil
		}
	case "revoke":
		if len(rest) == 2 && safeUnitRe.MatchString(rest[1]) {
			return nil
		}
	}
	return fmt.Errorf("easyrsa arguments are not permitted")
}

func policyOpenVPN(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "--version":
		return nil
	case len(args) == 3 && args[0] == "--genkey" && args[1] == "--secret" && args[2] == "ta.key":
		return nil
	}
	return fmt.Errorf("openvpn arguments are not permitted")
}

func policyCp(args []string) error {
	recursive := false
	if len(args) > 0 && args[0] == "-r" {
		recursive = true
		args = args[1:]
	}
	if len(args) != 2 {
		return fmt.Errorf("cp requires exactly one source and one destination")
	}
	src, dst := args[0], strings.TrimSuffix(args[1], "/")
	if recursive {
		if src == "/usr/share/easy-rsa" && dst == "/etc/openvpn/easy-rsa" {
			return nil
		}
		return fmt.Errorf("recursive copy is not permitted here")
	}
	if !pathUnder(src, append(tmpDirs(), "/etc/openvpn", "/etc/softrouter")...) {
		return fmt.Errorf("cp source is not permitted")
	}
	if !pathUnder(dst, "/etc/openvpn/server", "/etc/systemd/resolved.conf.d", "/etc/miniupnpd") {
		return fmt.Errorf("cp destination is not permitted")
	}
	return nil
}

func policyMkdir(args []string) error {
	if len(args) == 2 && args[0] == "-p" && pathUnder(args[1], "/etc/systemd/resolved.conf.d", "/etc/softrouter", "/etc/openvpn") {
		return nil
	}
	return fmt.Errorf("mkdir is only permitted as `mkdir -p` inside SoftRouter-managed directories")
}

func policyDnsmasq(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "-v":
		return nil
	case len(args) == 2 && args[0] == "--test" && strings.HasPrefix(args[1], "--conf-file=") &&
		pathUnder(strings.TrimPrefix(args[1], "--conf-file="), tmpDirs()...):
		return nil
	case len(args) == 4 && args[0] == "-C" && args[2] == "-x" &&
		pathUnder(args[1], "/run/softrouter") && pathUnder(args[3], "/run/softrouter"):
		return nil
	}
	return fmt.Errorf("dnsmasq arguments are not permitted")
}

func policyRadvd(args []string) error {
	if len(args) == 2 && args[0] == "--configtest" && strings.HasPrefix(args[1], "--config=") &&
		pathUnder(strings.TrimPrefix(args[1], "--config="), tmpDirs()...) {
		return nil
	}
	return fmt.Errorf("radvd arguments are not permitted")
}

func policyConntrack(args []string) error {
	if (len(args) == 1 && args[0] == "-L") ||
		(len(args) == 3 && args[0] == "-L" && args[1] == "-o" && args[2] == "extended") {
		return nil
	}
	return fmt.Errorf("conntrack arguments are not permitted")
}

// updateScriptArgsOK checks the optional `--branch main|Dev [--force]` tail.
func updateScriptArgsOK(args []string) bool {
	if len(args) < 2 || args[0] != "--branch" || (args[1] != "main" && args[1] != "Dev") {
		return false
	}
	rest := args[2:]
	return len(rest) == 0 || (len(rest) == 1 && rest[0] == "--force")
}

func policyUpdateScript(args []string) error {
	if !updateScriptArgsOK(args) {
		return fmt.Errorf("update.sh arguments are not permitted")
	}
	return nil
}

var (
	sysdUnitRe = regexp.MustCompile(`^--unit=softrouter-update-[0-9]{1,12}$`)
	sysdPropRe = regexp.MustCompile(`^(WorkingDirectory|Environment)=[A-Za-z0-9_./:=@+-]*$`)
)

// policySystemdRun only accepts the exact invocation applyUpdate() builds:
// a transient oneshot unit that runs <repo>/update.sh with a fixed property set.
func policySystemdRun(args []string) error {
	if len(args) < 4 || !sysdUnitRe.MatchString(args[0]) || args[1] != "--no-block" || args[2] != "--service-type=oneshot" {
		return fmt.Errorf("systemd-run is only permitted for SoftRouter updates")
	}
	i := 3
	for i+1 < len(args) && args[i] == "-p" {
		if !sysdPropRe.MatchString(args[i+1]) {
			return fmt.Errorf("systemd-run property %q is not permitted", args[i+1])
		}
		i += 2
	}
	if i >= len(args) {
		return fmt.Errorf("systemd-run requires the update script")
	}
	script := args[i]
	if !filepath.IsAbs(script) || filepath.Base(script) != "update.sh" || filepath.Clean(script) != script {
		return fmt.Errorf("systemd-run may only run update.sh")
	}
	if !updateScriptArgsOK(args[i+1:]) {
		return fmt.Errorf("update.sh arguments are not permitted")
	}
	return nil
}
