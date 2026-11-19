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
