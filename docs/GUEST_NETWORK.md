# Guest / IoT network isolation

An interface labelled **Guest**, **IoT** or **Isolated** (Interfaces page -> Label) is
not trusted like a LAN port. After the firewall is applied it can only:

| Direction | Allowed |
|-----------|---------|
| To the router | DHCP (udp 67) and DNS (udp/tcp 53) |
| Through the router | Internet (WAN interfaces) and the exceptions you add |

Everything else - SSH, the web UI, AdGuard's admin port, other subnets, LAN servers - is
dropped by the default-drop policy. Replies to connections a guest device started are
allowed by the existing `ct state established,related` rule. Nothing is forwarded *to*
the guest network from the LAN (so casting/control from the LAN to a guest device is blocked).

Interfaces without a label are still treated as LAN automatically (full trust), including
VLAN sub-interfaces such as `eno1.20`. Label them Guest/IoT to isolate them.

## Exceptions

Open **Guest / IoT** in the sidebar and choose **Add Exception**:

* **Destination**: an IPv4 address or network, e.g. `192.168.3.102` or `192.168.3.0/24`
* **Protocol**: TCP or UDP
* **Ports**: one or more, e.g. `443` or `80, 443`
* **Applies to**: with two or more isolated networks, tick the ones the exception covers (for example Guest but not IoT). Leave all unticked to cover every isolated network. An exception limited to a network that no longer exists applies nowhere.

Each change is validated, saved to `/etc/softrouter/guest_access.json` and applied to the
firewall immediately. If the firewall rejects a change, it is rolled back. Exceptions can
be switched off without deleting them. They survive reboots and every firewall
regeneration, and each add/edit/remove is written to the audit log.

Check the result with:

```
sudo nft list chain inet softrouter forward | grep -i guest
sudo nft list chain inet softrouter input   | grep -i guest
```

## DNS tip

Guest clients should use the router (or your DNS server) for DNS. If a split-DNS rewrite
(e.g. in AdGuard Home) points a name at an internal reverse proxy, make sure the guest
DHCP scope hands out that DNS server, and that the proxy only serves what guests may see.

## DNS control (optional, off by default)

On the same page, three switches apply to **every** isolated network:

| Switch | What it does |
|--------|--------------|
| Force DNS through the router | Redirects DNS (port 53) that devices send to any other server (such as 8.8.8.8) to the router, so your ad blocker sees every query. DNS that cannot be redirected, such as IPv6 DNS to an outside server, is dropped. |
| Block DNS-over-TLS and DNS-over-QUIC | Drops port 853. |
| Block DNS-over-HTTPS to well-known resolvers | Drops HTTPS and QUIC to the published addresses of Cloudflare, Google, Quad9, OpenDNS, AdGuard DNS, CleanBrowsing and Control D. |

Limits: the DoH list only covers resolvers with known addresses. A resolver that shares an address
with ordinary websites is not caught by it; block those by name in your ad blocker's lists. A device
that insists on its own encrypted DNS and has nothing else to fall back on may lose DNS entirely, which
is the point of the setting. Each rule has a counter, so you can see attempts with
`sudo nft list chain inet softrouter forward | grep -i guest` and
`sudo nft list chain ip softrouter_nat prerouting | grep -i guest`.

The settings are stored next to the exceptions in `/etc/softrouter/guest_access.json`, survive every
firewall regeneration, and are applied with the same automatic rollback as exceptions.
