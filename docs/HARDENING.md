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

## Upgrade notes
* A pre-upgrade `table ip nat` stays loaded until reboot; the new rules use `ip softrouter_nat`. Reboot once after upgrading.
* Install Go with `golang-1.24-go` (`/usr/lib/go-1.24/bin`).

## Not changed (decision needed)
* The privilege model: the installed unit runs as `softrouter` with `sudo NOPASSWD: ALL`, and the Go allowlist still contains root-equivalent tools (`systemd-run`, `cp`, `curl`, `tail`, `journalctl`). Narrowing sudoers alone would not add real separation.
* `install.sh` installs UniFi with `--allow-unauthenticated` / `--allow-insecure-repositories` on Trixie.
