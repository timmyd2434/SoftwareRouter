package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxOVPNConfigSize = 256 << 10 // 256 KiB
	ovpnClientDir     = "/etc/openvpn/client/"
)

// ovpnAllowedDirectives is a strict allowlist. Anything not listed is rejected.
// Directives that can execute code or touch arbitrary files (plugin, up, down,
// route-up, tls-verify, auth-user-pass-verify, script-security, setenv, config,
// management, daemon, chroot, writepid, log, status, askpass, ...) are
// intentionally absent and therefore rejected.
var ovpnAllowedDirectives = map[string]bool{
	"client": true, "tls-client": true, "pull": true, "remote": true, "remote-random": true,
	"proto": true, "port": true, "rport": true, "nobind": true, "resolv-retry": true,
	"connect-retry": true, "connect-retry-max": true, "server-poll-timeout": true,
	"cipher": true, "data-ciphers": true, "data-ciphers-fallback": true, "ncp-ciphers": true,
	"auth": true, "tls-version-min": true, "tls-cipher": true, "tls-ciphersuites": true,
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"crl-verify": true, "key-direction": true,
	"comp-lzo": true, "compress": true, "verb": true, "mute": true,
	"persist-key": true, "persist-tun": true, "remote-cert-tls": true,
	"verify-x509-name": true, "auth-nocache": true, "auth-retry": true,
	"ping": true, "ping-restart": true, "ping-exit": true, "keepalive": true,
	"reneg-sec": true, "explicit-exit-notify": true, "mssfix": true, "tun-mtu": true,
	"fragment": true, "sndbuf": true, "rcvbuf": true, "fast-io": true, "disable-occ": true,
	"route-nopull": true, "redirect-gateway": true, "pull-filter": true,
}

// directives whose argument may be a file path
var ovpnPathDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "crl-verify": true,
}

// inline blocks we accept (<ca> ... </ca>)
var ovpnInlineBlocks = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "crl-verify": true,
}

// directives that the installer controls itself: stripped silently from uploads.
var ovpnStripped = map[string]bool{"dev": true, "auth-user-pass": true, "route-noexec": true}

// sanitizeOpenVPNConfig validates an uploaded .ovpn file against the allowlist
// and returns the cleaned lines. Any violation returns an error (HTTP 400).
func sanitizeOpenVPNConfig(content string) ([]string, error) {
	if len(content) > maxOVPNConfigSize {
		return nil, fmt.Errorf("config file too large (max 256 KiB)")
	}
	if strings.ContainsRune(content, 0) {
		return nil, fmt.Errorf("config contains NUL bytes")
	}

	var out []string
	inBlock := ""
	for i, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		lineNo := i + 1
		if strings.ContainsRune(raw, '\r') {
			return nil, fmt.Errorf("line %d: stray carriage return", lineNo)
		}
		line := strings.TrimSpace(raw)

		// Inside an inline <block>: only PEM / base64 / hex key material allowed
		if inBlock != "" {
			if line == "</"+inBlock+">" {
				inBlock = ""
				out = append(out, line)
				continue
			}
			for _, r := range line {
				ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
					r == '+' || r == '/' || r == '=' || r == '-' || r == ' ' || r == '#' || r == ':' || r == '.' || r == '_'
				if !ok {
					return nil, fmt.Errorf("line %d: illegal character in inline %s block", lineNo, inBlock)
				}
			}
			out = append(out, line)
			continue
		}

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue // drop comments/blank lines
		}

		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
			if !ovpnInlineBlocks[name] {
				return nil, fmt.Errorf("line %d: inline block <%s> is not allowed", lineNo, name)
			}
			inBlock = name
			out = append(out, line)
			continue
		}

		fields := strings.Fields(line)
		directive := strings.TrimPrefix(fields[0], "--")
		args := fields[1:]

		if ovpnStripped[directive] {
			continue
		}
		if !ovpnAllowedDirectives[directive] {
			return nil, fmt.Errorf("line %d: directive %q is not permitted", lineNo, directive)
		}
		for _, a := range args {
			if strings.ContainsAny(a, "\"'`$;|&<>\\") {
				return nil, fmt.Errorf("line %d: illegal characters in argument of %q", lineNo, directive)
			}
		}

		switch {
		case directive == "remote":
			if len(args) < 1 || len(args) > 3 {
				return nil, fmt.Errorf("line %d: malformed remote", lineNo)
			}
			if err := validateHostOrIP(args[0]); err != nil {
				return nil, fmt.Errorf("line %d: invalid remote host", lineNo)
			}
			if len(args) >= 2 {
				if _, err := validatePortString(args[1]); err != nil {
					return nil, fmt.Errorf("line %d: invalid remote port", lineNo)
				}
			}
			if len(args) == 3 {
				switch args[2] {
				case "udp", "tcp", "udp4", "udp6", "tcp4", "tcp6", "tcp-client":
				default:
					return nil, fmt.Errorf("line %d: invalid remote protocol", lineNo)
				}
			}
		case ovpnPathDirectives[directive]:
			if len(args) >= 1 {
				if err := validateOVPNPath(args[0]); err != nil {
					return nil, fmt.Errorf("line %d: %v", lineNo, err)
				}
			}
		case directive == "port" || directive == "rport":
			if len(args) != 1 {
				return nil, fmt.Errorf("line %d: malformed %s", lineNo, directive)
			}
			if _, err := strconv.Atoi(args[0]); err != nil {
				return nil, fmt.Errorf("line %d: invalid port", lineNo)
			}
		}
		out = append(out, strings.Join(fields, " "))
	}
	if inBlock != "" {
		return nil, fmt.Errorf("unterminated <%s> block", inBlock)
	}
	return out, nil
}

// validateOVPNPath only accepts files under /etc/openvpn/client/ (no traversal).
func validateOVPNPath(p string) error {
	if p == "[inline]" {
		return nil
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("path traversal not permitted")
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("relative file paths are not permitted; use inline blocks or /etc/openvpn/client/")
	}
	if !strings.HasPrefix(clean, ovpnClientDir) {
		return fmt.Errorf("file paths must be under %s", ovpnClientDir)
	}
	return nil
}
