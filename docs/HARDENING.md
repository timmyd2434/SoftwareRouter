# Hardening changes (Debian 13 "Trixie")

Applies on top of `main` @ df03d0d. Run `go mod tidy` in `backend/` once (argon2 pulls in `golang.org/x/sys`).

## Behaviour changes you will notice
| Area | Before | After |
|---|---|---|
| WAN SSH / DNS | Always open (several code paths) | Open only during a 60-minute **provisioning window** after a fresh install, or if `allow_wan_ssh` / `allow_wan_dns` are set |
| Existing installs | n/a | Missing fields decode as `false`, so WAN SSH/DNS **close on upgrade**. Set `"allow_wan_ssh": true` in `/etc/softrouter/config.json` if you rely on it |
| Firewall apply | `flush ruleset` (wipes Docker, CrowdSec, miniupnpd) | Only `inet softrouter` and `ip softrouter_nat` are replaced |
| Firewall "disabled" | Empty ruleset (no NAT, WAN open) | Safe baseline: WAN input drop, NAT and LAN forwarding kept |
| Sessions | 24 h sliding, token in localStorage + JSON | 30 min idle / 12 h absolute, HttpOnly cookie only |
| Password change | Sessions survived | All sessions revoked; UI asks for current password (it never sent it before, so the change always failed) |
| Backups | PBKDF2 4096, includes `token_secret.key` + credential hash | Argon2id (64 MiB, t=3, p=4), header authenticated; secrets excluded. Old `SRBKP01` files still restore |
| OpenVPN client upload | Free-form directives (`up`, `plugin`, ... ran as root) | Strict allowlist; anything else is a 400 |
| CSP | Overridden by a looser inner header (`unsafe-inline` scripts) | One middleware; `script-src 'self'`; Inter font self-hosted |

## Operator controls
* `POST /api/system/lockdown` `{"close_webui_wan": bool}` closes provisioning (also a banner + wizard checkbox).
* `config.json`: `allowed_hosts` (Host allowlist; IPs and `localhost` always pass), `allow_insecure_webhook`.
* Rate limits: backup create 2 / 10 min; restore, update, speedtest 5 / 10 min and one at a time.

## Installer: CrowdSec port clash
CrowdSec's local API defaults to `127.0.0.1:8080`, the same port as SoftwareRouter's HTTP->HTTPS redirect server, and `install.sh` ended with `fuser -k 8080/tcp`, which killed it. The installer now moves CrowdSec to 9081 (config, CLI credentials, firewall bouncer) and only frees port 80.

## Privileged command policy (`backend/priv_policy.go`)
`allowedCommands` only named binaries; several were root-equivalent with free arguments (`systemd-run`, `cp`, `curl`, `tail`, `journalctl`, `mkdir`, `openvpn`, `ip netns exec`). Every command now has an argument policy that accepts only the shapes the code actually uses, and a command with no policy is refused. Examples: `tail` only reads the Suricata eve log; `journalctl` only `-u softrouter`; `cp` only between fixed directories; `curl` only https (plus the public-IP lookup) and only writes to fixed paths; `systemd-run` only the exact update invocation; `systemctl` only known units and actions; `sysctl` only four keys with 0/1. `suricata` (never called) was removed from the allowlist.
`priv_policy_test.go` replays every call shape found in the code (must pass) and ~90 abuse attempts (must be refused). If you add a new privileged call and it is refused, the log line `SECURITY: arguments for '<cmd>' rejected: <reason>` says why; extend the matching policy.
Also fixed: the non-root update path passed an absolute `.../update.sh` that the old allowlist never matched.
Still open: sudoers (`NOPASSWD: ALL`) is the real boundary if the backend process itself is compromised.

## WireGuard: client files import without edits
`backend/wireguard_peers.go`. The generated client config now has the configured public endpoint (static IP, DDNS name or auto-detected IP; the browser's Host header is no longer used, and generation is refused if no endpoint can be determined). Addresses are allocated from the peers actually in `wg0.conf` (lowest free 10.8.0.N), duplicate names are refused, deleting a client removes its `[Peer]` block and live peer, and new peers are loaded with `wg set` (the old `wg syncconf` call always failed on a wg-quick style file). The firewall now trusts `wg0` for input and forwarding, and the WAN `udp 51820` rule exists whenever `wg0.conf` does. Peers added by hand to `wg0.conf` keep working but are not shown in the client list.
Public endpoint hint: if you use a Cloudflare hostname, set the record to DNS only (not proxied); the proxy does not carry UDP.

## Upgrade notes
* A pre-upgrade `table ip nat` stays loaded until reboot; the new rules use `ip softrouter_nat`. Reboot once after upgrading.
* Install Go with `golang-1.24-go` (`/usr/lib/go-1.24/bin`).

## Not changed (decision needed)
* The privilege model: the installed unit runs as `softrouter` with `sudo NOPASSWD: ALL`, and the Go allowlist still contains root-equivalent tools (`systemd-run`, `cp`, `curl`, `tail`, `journalctl`). Narrowing sudoers alone would not add real separation.
* `install.sh` installs UniFi with `--allow-unauthenticated` / `--allow-insecure-repositories` on Trixie.
