package main

import (
	"fmt"
	"strings"
)

// GuestSettings are options that apply to every isolated (Guest/IoT) network. All are off by
// default, so installing an update never changes how existing devices behave.
type GuestSettings struct {
	// EnforceDNS sends every DNS query (port 53) from isolated networks to the router, whatever
	// server the device asked for, and drops DNS that cannot be redirected (such as IPv6), so a
	// device cannot bypass the ad blocker with a hard-coded server like 8.8.8.8.
	EnforceDNS bool `json:"enforce_dns"`
	// BlockDoT drops DNS-over-TLS and DNS-over-QUIC (port 853).
	BlockDoT bool `json:"block_dot"`
	// BlockDoH drops HTTPS and QUIC to well-known public DNS resolvers (DNS-over-HTTPS).
	BlockDoH bool `json:"block_doh"`
}

// dohResolversV4 and dohResolversV6 are the addresses of large public resolvers that also speak
// DNS-over-HTTPS. They catch devices with a hard-coded resolver. They cannot catch a resolver that
// shares an address with ordinary websites (for example behind a CDN); the ad blocker's own lists
// cover those by name. Sources: the providers' published resolver addresses.
var dohResolversV4 = []string{
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"1.1.1.2", "1.0.0.2", // Cloudflare (malware blocking)
	"1.1.1.3", "1.0.0.3", // Cloudflare (malware and adult content blocking)
	"8.8.8.8", "8.8.4.4", // Google
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
	"208.67.222.123", "208.67.220.123", // OpenDNS FamilyShield
	"94.140.14.14", "94.140.15.15", // AdGuard DNS
	"94.140.14.140", "94.140.14.141", // AdGuard DNS (unfiltered)
	"94.140.14.15", "94.140.15.16", // AdGuard DNS (family)
	"185.228.168.9", "185.228.169.9", // CleanBrowsing
	"76.76.2.0", "76.76.10.0", // Control D
}

var dohResolversV6 = []string{
	"2606:4700:4700::1111", "2606:4700:4700::1001", // Cloudflare
	"2001:4860:4860::8888", "2001:4860:4860::8844", // Google
	"2620:119:35::35", "2620:119:53::53", // OpenDNS
	"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", // AdGuard DNS
	"2a0d:2a00:1::2", "2a0d:2a00:2::2", // CleanBrowsing
}

// writeGuestDNSRedirect emits the NAT rules that send guest DNS to the router. It goes in the
// prerouting chain of the IPv4 NAT table. IPv6 DNS cannot be redirected there, so
// writeGuestDNSBlocks drops it instead.
func writeGuestDNSRedirect(b *strings.Builder, guests []string, s GuestSettings) {
	if !s.EnforceDNS {
		return
	}
	for _, g := range guests {
		for _, proto := range []string{"udp", "tcp"} {
			b.WriteString(fmt.Sprintf("    iifname \"%s\" %s dport 53 fib daddr type != local counter redirect to :53 comment \"Guest DNS enforcement\"\n", g, proto))
		}
	}
}

// writeGuestDNSBlocks emits the forward-chain drops. They must come before the guest accept rules.
func writeGuestDNSBlocks(b *strings.Builder, guests []string, s GuestSettings) {
	for _, g := range guests {
		if s.EnforceDNS {
			// Anything still headed for port 53 after the redirect (IPv6, or non-redirectable) is dropped.
			b.WriteString(fmt.Sprintf("    iifname \"%s\" meta l4proto { tcp, udp } th dport 53 counter drop comment \"Guest DNS enforcement\"\n", g))
		}
		if s.BlockDoT {
			b.WriteString(fmt.Sprintf("    iifname \"%s\" meta l4proto { tcp, udp } th dport 853 counter drop comment \"Guest DoT and DoQ block\"\n", g))
		}
		if s.BlockDoH {
			v4 := strings.Join(dohResolversV4, ", ")
			v6 := strings.Join(dohResolversV6, ", ")
			for _, proto := range []string{"tcp", "udp"} { // udp covers HTTP/3
				b.WriteString(fmt.Sprintf("    iifname \"%s\" ip daddr { %s } %s dport 443 counter drop comment \"Guest DoH block\"\n", g, v4, proto))
				b.WriteString(fmt.Sprintf("    iifname \"%s\" ip6 daddr { %s } %s dport 443 counter drop comment \"Guest DoH block\"\n", g, v6, proto))
			}
		}
	}
}
