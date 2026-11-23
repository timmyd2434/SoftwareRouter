# Running the web service without root

By default SoftRouter's web service runs as root. This switches it to the unprivileged
`softrouter` account. Everything that needs root (firewall, interfaces, services, VPN and DHCP
config files) then goes through the privileged helper (`softrouter-privhelper.service`), which
checks each request against the same allowlist and content rules the backend uses.

**What it protects against:** a bug in the web-facing code no longer gives an attacker root, the
ability to load kernel modules, or the ability to write config that root later runs (a WireGuard
`PostUp` line, a dnsmasq `dhcp-script`, a systemd `ExecStart`). The service also runs with
`NoNewPrivileges`, a read-only file system apart from its own directories, and no capabilities
except binding ports 80/443.

**What it does not do:** the helper is only as strict as its rules. An attacker who controls the
web service can still ask for anything those rules allow (for example changing a firewall rule,
which an authenticated admin can do anyway).

## Before you start

1. The helper is enabled and running: `systemctl is-active softrouter-privhelper`.
2. You have used the dashboard for a few days with the helper enabled, and this prints `0`:
   `journalctl -u softrouter --since "3 days ago" | grep -c PRIVHELPER-SHADOW`
3. You have SSH or console access that does not depend on the web UI.

## Apply

```
sudo /opt/SoftwareRouter/scripts/softrouter-nonroot apply --dry-run   # show what it would do
sudo /opt/SoftwareRouter/scripts/softrouter-nonroot apply
```

`apply` refuses to continue if the helper is down or recent `PRIVHELPER-SHADOW` warnings exist
(`--force` overrides the second check). It then:

1. creates the `softrouter` user and group if missing;
2. gives that user ownership of the service's own directories: `/etc/softrouter`,
   `/var/log/softrouter`, `/var/backups/softrouter`, `/var/www/softrouter/vpn_configs`;
3. installs `systemd/softrouter-nonroot.conf` as a systemd drop-in
   (`/etc/systemd/system/softrouter.service.d/10-nonroot.conf`), which survives updates;
4. restarts the helper and the service;
5. verifies that the service runs as `softrouter`, stays up for several seconds, and that
   privileged commands are reaching the helper. **If any check fails it rolls itself back.**

## Check it worked

```
sudo /opt/SoftwareRouter/scripts/softrouter-nonroot status
ps -o user=,cmd= -p "$(systemctl show -p MainPID --value softrouter)"
```

Then use the features you rely on: change a firewall rule and a DHCP setting, add and remove a
WireGuard client, toggle a guest exception, run a web update. Look for problems with:

```
journalctl -u softrouter --since "10 min ago" | grep -iE "error|denied|read-only|helper"
journalctl -u softrouter-privhelper --since "10 min ago" | grep -i rejected
```

A message such as `read-only file system` means the service tried to write somewhere outside its
own directories; send it to me and roll back in the meantime.

## Roll back

```
sudo /opt/SoftwareRouter/scripts/softrouter-nonroot rollback
```

Removes the drop-in and restarts the service as root. File ownership stays as it is, which root
can still read and write. After a rollback you can safely apply again later.

## Things that behave differently without root

* **Updates** still run as root (in their own transient unit) via the helper. `update.sh` hands
  ownership of the service's directories back after each update, and never starts a root copy of
  the backend by hand while this mode is on.
* **"Check for updates"** cannot fetch into the repository (it belongs to another user), so it asks
  GitHub directly (`git ls-remote`). The "commits behind" number is exact only when those commits
  are already in the local clone; otherwise it shows that at least one is new.
* **No sudo.** If the helper is down, privileged actions fail immediately with a clear message
  instead of falling back to sudo. `systemctl restart softrouter-privhelper` fixes it.
* **First-boot fallback network** (the temporary 192.168.254.x DHCP offered on a brand-new,
  unconfigured router) cannot stop a previous copy of its dnsmasq; this only matters if first boot
  runs repeatedly.
* WireGuard and OpenVPN config files stay root-owned. The service reads `wg0.conf` and the OpenVPN
  certificate files through the helper, and writes config only through it.
