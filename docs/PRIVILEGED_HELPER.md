# Privileged helper (opt-in, stage 1)

`softrouter-privhelper.service` is a small root-only daemon (`softrouter-backend privhelper`)
that listens on a Unix socket, `/run/softrouter-priv/priv.sock` (directory `root:softrouter`
0750, socket 0660). The backend asks it to run commands, and it:

* checks the caller's uid with `SO_PEERCRED` (only root and the `softrouter` user are accepted);
* re-validates every command against the same allowlist and argument policy the backend uses
  (`validateCommand`), so a compromised backend cannot widen what is allowed;
* runs it with the same timeouts, a size cap on output, and an allowlisted working directory;
* offers file operations (write, append, mkdir, remove, copy, read) restricted to managed paths,
  with content checks (for example it rejects WireGuard hooks other than the scoped masquerade
  rule, dnsmasq script directives, and OpenVPN plugin/script directives).

## Status: nothing changes until you enable it

The service unit is installed by `install.sh` and `update.sh` but **not enabled**. The backend
still runs as root, and it only uses the helper when the socket exists. If the helper is stopped
or unreachable the backend runs commands itself, exactly as before. The helper only starts to
reduce risk once the backend itself runs as an unprivileged user (a later stage).

## Trying it

```
sudo systemctl enable --now softrouter-privhelper
sudo journalctl -u softrouter-privhelper -f     # every command is logged as it is run
```

Use the dashboard as usual (firewall, interfaces, VPN, DHCP). Commands now flow through the
helper, and any that the policy rejects show up in the journal as `command rejected`.
To go back: `sudo systemctl disable --now softrouter-privhelper`.

The update script stops and restarts the helper around binary replacement when it is enabled.

## Not done yet

* File writes the backend does directly (for example `/etc/nftables.conf`, dnsmasq config, bonding
  settings under `/sys`) do not use the helper yet; that is the inventory step before the backend
  can drop root.
* The helper unit has no sandboxing directives yet, because the commands it runs need broad
  access. They can be added after the backend is unprivileged.
