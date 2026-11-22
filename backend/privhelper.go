package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// privSocketPath lives in its own runtime directory (created by softrouter-privhelper.service).
// It must not share /run/softrouter with the backend unit, because systemd deletes that
// directory whenever the backend restarts, which would remove the helper's socket.
// It is a variable so tests can point it at a temporary socket.
var privSocketPath = "/run/softrouter-priv/priv.sock"

// PrivRequest is the JSON request sent by the backend to the helper.
// The zero Op is equivalent to "exec" for backwards compatibility.
type PrivRequest struct {
	Op      string   `json:"op,omitempty"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Stdin   []byte   `json:"stdin,omitempty"`
	// Combined merges stderr into stdout (like exec.Cmd.CombinedOutput).
	Combined bool `json:"combined,omitempty"`

	Path    string `json:"path,omitempty"`
	NewPath string `json:"new_path,omitempty"`
	Content []byte `json:"content,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
}

// PrivResponse is the JSON response sent by the helper to the backend.
type PrivResponse struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Data     []byte `json:"data,omitempty"`
}

// managedDirs are the only directories the helper will write to or remove.
// Everything else is either owned by the unprivileged backend or denied.
var managedDirs = []string{
	"/etc/dnsmasq.d",
	"/etc/frr",
	"/etc/miniupnpd",
	"/etc/openvpn",
	"/etc/suricata",
	"/etc/systemd/resolved.conf.d",
	"/etc/systemd/system/suricata.service.d",
	"/etc/unbound",
	"/etc/wireguard",
}

var managedFiles = map[string]bool{
	"/etc/nftables.conf":        true,
	"/etc/nftables.conf.backup": true,
	"/etc/radvd.conf":           true,
	"/etc/resolv.conf":          true,
}

// Paths that the helper may read from when copying files.
var managedCopySources = []string{
	"/etc/openvpn",
	"/etc/softrouter/tls",
}

const suricataIPSOverride = `[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
`

// runPrivHelper runs the privileged helper daemon. It must be started as root.
func runPrivHelper() {
	if os.Getuid() != 0 {
		log.Fatal("Privileged helper must run as root")
	}

	sockDir := filepath.Dir(privSocketPath)
	if err := os.MkdirAll(sockDir, 0750); err != nil {
		log.Fatalf("Failed to create socket dir: %v", err)
	}

	// The runtime directory is root:softrouter 0750. The backend can traverse
	// it and connect to the socket, but cannot create or unlink entries here,
	// so the helper socket cannot be replaced by the unprivileged service.
	// Transient files belong in /run/softrouter/tmp (owned by softrouter).
	var sockGID int
	if grp, err := user.LookupGroup("softrouter"); err == nil {
		if gid, err := strconv.Atoi(grp.Gid); err == nil {
			sockGID = gid
			_ = os.Chown(sockDir, 0, gid)
		}
	}
	_ = os.Chmod(sockDir, 0750)

	os.Remove(privSocketPath) // Remove stale socket

	listener, err := net.Listen("unix", privSocketPath)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", privSocketPath, err)
	}
	defer listener.Close()

	// Socket is root:softrouter 0660. The backend can connect as a group
	// member but cannot modify the socket file itself.
	if err := os.Chown(privSocketPath, 0, sockGID); err != nil {
		log.Printf("Warning: failed to chown socket: %v", err)
	}
	if err := os.Chmod(privSocketPath, 0660); err != nil {
		log.Fatalf("Failed to chmod socket: %v", err)
	}

	log.Printf("Privileged helper listening on %s (uid=0 gid=%d)", privSocketPath, sockGID)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("Privileged helper shutting down")
		os.Remove(privSocketPath)
		os.Exit(0)
	}()

	// Allowed users (by UID). Only the dedicated service account may connect.
	allowedUIDs := map[int]bool{}
	if u, err := user.Lookup("softrouter"); err == nil {
		if uid, err := strconv.Atoi(u.Uid); err == nil {
			allowedUIDs[uid] = true
		}
	}
	allowedUIDs[0] = true // root (manual diagnostics)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handlePrivConn(conn, allowedUIDs)
	}
}

func handlePrivConn(conn net.Conn, allowedUIDs map[int]bool) {
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		log.Println("Not a unix connection")
		return
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		log.Printf("SyscallConn error: %v", err)
		return
	}

	var cred *unix.Ucred
	var credErr error
	rawConn.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if credErr != nil || cred == nil {
		log.Printf("SO_PEERCRED error: %v", credErr)
		return
	}
	if !allowedUIDs[int(cred.Uid)] {
		log.Printf("Unauthorized connection from uid %d", cred.Uid)
		_ = json.NewEncoder(conn).Encode(PrivResponse{ExitCode: 1, Stderr: "unauthorized"})
		return
	}

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	var req PrivRequest
	// Bound the request size (16 MiB content limit plus JSON overhead).
	if err := json.NewDecoder(io.LimitReader(conn, 32<<20)).Decode(&req); err != nil {
		log.Printf("Decode error: %v", err)
		_ = json.NewEncoder(conn).Encode(PrivResponse{ExitCode: 1, Stderr: "invalid request"})
		return
	}

	resp := handlePrivRequest(req)

	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("Response encode error: %v", err)
	}
}

func handlePrivRequest(req PrivRequest) PrivResponse {
	if req.Op == "" {
		req.Op = "exec"
	}

	var err error
	switch req.Op {
	case "exec":
		return executePrivCommand(req)
	case "write":
		err = helperWriteFile(req.Path, req.Content, os.FileMode(req.Mode), false)
	case "append":
		err = helperWriteFile(req.Path, req.Content, os.FileMode(req.Mode), true)
	case "mkdir":
		err = helperMkdirDir(req.Path, os.FileMode(req.Mode))
	case "remove":
		err = helperRemovePath(req.Path, false)
	case "remove_all":
		err = helperRemovePath(req.Path, true)
	case "rename":
		err = helperRenamePath(req.Path, req.NewPath)
	case "copy":
		err = helperCopyPath(req.Path, req.NewPath)
	case "read":
		data, readErr := helperReadFile(req.Path)
		if readErr != nil {
			log.Printf("[PRIVHELPER] read %s -> %v", req.Path, readErr)
			return PrivResponse{ExitCode: 1, Stderr: readErr.Error()}
		}
		return PrivResponse{ExitCode: 0, Data: data}
	default:
		err = fmt.Errorf("unknown privileged operation: %s", req.Op)
	}

	if err != nil {
		log.Printf("[PRIVHELPER] %s %s -> %v", req.Op, req.Path, err)
		return PrivResponse{ExitCode: 1, Stderr: err.Error()}
	}
	return PrivResponse{ExitCode: 0}
}

func executePrivCommand(req PrivRequest) PrivResponse {
	if err := validateCommand(req.Command, req.Args); err != nil {
		log.Printf("[PRIVHELPER] command rejected: %v", err)
		return PrivResponse{ExitCode: 1, Stderr: err.Error()}
	}
	if req.Dir != "" {
		if err := validateWorkingDir(req.Dir); err != nil {
			return PrivResponse{ExitCode: 1, Stderr: err.Error()}
		}
	}

	ctx, cancel := getCommandContext(req.Command)
	defer cancel()

	// #nosec G204 G702: command and args are validated against a strict allowlist.
	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	cmd.Dir = req.Dir
	if len(req.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}
	stdout := &limitedBuffer{max: maxHelperOutput}
	stderr := &limitedBuffer{max: maxHelperOutput}
	cmd.Stdout = stdout
	if req.Combined {
		cmd.Stderr = stdout // same writer: output is interleaved in order
	} else {
		cmd.Stderr = stderr
	}

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	log.Printf("[PRIVHELPER] %s %s -> exit %d", req.Command, strings.Join(req.Args, " "), exitCode)
	return PrivResponse{ExitCode: exitCode, Stdout: stdout.buf.String(), Stderr: stderr.buf.String()}
}

func validateWorkingDir(dir string) error {
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.Contains(dir, "..") {
		return fmt.Errorf("SECURITY: invalid working directory: %s", dir)
	}
	allowed := []string{"/etc/openvpn", "/opt/"}
	for _, prefix := range allowed {
		if dir == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(dir, prefix) {
			return nil
		}
	}
	return fmt.Errorf("SECURITY: working directory not allowed: %s", dir)
}

func validateManagedPath(path string, forCopySource bool) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("SECURITY: path must be absolute")
	}
	if filepath.Clean(path) != path || strings.Contains(path, "..") {
		return fmt.Errorf("SECURITY: path must be clean and must not contain '..': %s", path)
	}
	// The helper socket, its runtime directory, and the softrouter config
	// directory are never writable through the helper. Those files are owned
	// by root and provisioned at install time.
	if path == privSocketPath || path == filepath.Dir(privSocketPath) ||
		strings.HasPrefix(path, filepath.Dir(privSocketPath)+"/") {
		return fmt.Errorf("SECURITY: runtime directory is not writable through the helper: %s", path)
	}
	if managedFiles[path] {
		return nil
	}
	for _, dir := range managedDirs {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			switch {
			case strings.HasPrefix(path, "/etc/dnsmasq.d/"):
				if !strings.HasSuffix(path, ".conf") {
					return fmt.Errorf("SECURITY: only .conf files are allowed in /etc/dnsmasq.d")
				}
			case strings.HasPrefix(path, "/etc/wireguard/"):
				if !strings.HasSuffix(path, ".conf") {
					return fmt.Errorf("SECURITY: only .conf files are allowed in /etc/wireguard")
				}
			case strings.HasPrefix(path, "/etc/systemd/resolved.conf.d/"):
				if path != "/etc/systemd/resolved.conf.d/softrouter-dns-privacy.conf" &&
					path != "/etc/systemd/resolved.conf.d/softrouter-no-stub.conf" {
					return fmt.Errorf("SECURITY: only SoftRouter resolved drop-ins are allowed")
				}
			case strings.HasPrefix(path, "/etc/systemd/system/suricata.service.d/"):
				if path != "/etc/systemd/system/suricata.service.d/override.conf" {
					return fmt.Errorf("SECURITY: only the SoftRouter Suricata override is allowed")
				}
			case strings.HasPrefix(path, "/etc/unbound/"):
				if path != "/etc/unbound/unbound.conf.d" &&
					path != "/etc/unbound/unbound.conf.d/softrouter.conf" {
					return fmt.Errorf("SECURITY: only the SoftRouter Unbound drop-in is allowed")
				}
			}
			return nil
		}
	}
	if forCopySource {
		for _, dir := range managedCopySources {
			if path == dir || strings.HasPrefix(path, dir+"/") {
				return nil
			}
		}
	}
	return fmt.Errorf("SECURITY: path not allowed: %s", path)
}

// validateManagedReadPath restricts privileged reads to the small set of PKI
// files the backend needs to build client profiles. Server and CA private keys
// are deliberately excluded.
func validateManagedReadPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "..") {
		return fmt.Errorf("SECURITY: invalid read path: %s", path)
	}
	allowedFiles := map[string]bool{
		"/etc/openvpn/server/ca.crt":          true,
		"/etc/openvpn/server/ta.key":          true,
		"/etc/openvpn/server/crl.pem":         true,
		"/etc/openvpn/easy-rsa/pki/index.txt": true,
	}
	if allowedFiles[path] {
		return nil
	}
	const issuedPrefix = "/etc/openvpn/easy-rsa/pki/issued/"
	const privatePrefix = "/etc/openvpn/easy-rsa/pki/private/"
	var name string
	switch {
	case strings.HasPrefix(path, issuedPrefix) && strings.HasSuffix(path, ".crt"):
		name = strings.TrimSuffix(strings.TrimPrefix(path, issuedPrefix), ".crt")
	case strings.HasPrefix(path, privatePrefix) && strings.HasSuffix(path, ".key"):
		name = strings.TrimSuffix(strings.TrimPrefix(path, privatePrefix), ".key")
	default:
		return fmt.Errorf("SECURITY: read path not allowed: %s", path)
	}
	if !validEasyRSAClientName(name) {
		return fmt.Errorf("SECURITY: read path not allowed: %s", path)
	}
	return nil
}

func helperReadFile(path string) ([]byte, error) {
	if err := validateManagedReadPath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func validateManagedContent(path string, content []byte) error {
	if len(content) > 16*1024*1024 {
		return fmt.Errorf("SECURITY: content too large")
	}
	if bytes.IndexByte(content, 0) >= 0 {
		return fmt.Errorf("SECURITY: content contains NUL bytes")
	}
	s := string(content)

	switch {
	case strings.HasPrefix(path, "/etc/dnsmasq.d/"):
		return validateDnsmasqConf(s)
	case strings.HasPrefix(path, "/etc/wireguard/"):
		return validateWireGuardConf(s)
	case strings.HasPrefix(path, "/etc/openvpn/"):
		return validateOpenVPNFile(path, s)
	case path == "/etc/systemd/system/suricata.service.d/override.conf":
		if strings.TrimSpace(s) != strings.TrimSpace(suricataIPSOverride) {
			return fmt.Errorf("SECURITY: Suricata override content is not the approved template")
		}
	case path == "/etc/systemd/resolved.conf.d/softrouter-dns-privacy.conf":
		return validateResolvedConf(s)
	case path == "/etc/systemd/resolved.conf.d/softrouter-no-stub.conf":
		if strings.TrimSpace(s) != "[Resolve]\nDNSStubListener=no" && strings.TrimSpace(s) != "DNSStubListener=no" {
			return fmt.Errorf("SECURITY: unexpected resolved stub configuration")
		}
	case path == "/etc/resolv.conf":
		if strings.TrimSpace(s) != "nameserver 127.0.0.1" {
			return fmt.Errorf("SECURITY: /etc/resolv.conf may only point at the local resolver")
		}
	case strings.HasPrefix(path, "/etc/suricata/"):
		return validateSuricataConf(s)
	case path == "/etc/nftables.conf":
		return validateNftablesConf(s)
	case path == "/etc/radvd.conf":
		return validateRadvdConf(s)
	case strings.HasPrefix(path, "/etc/frr/"):
		return validateFRRConf(s)
	case strings.HasPrefix(path, "/etc/miniupnpd/"):
		return validateMiniupnpdConf(s)
	}
	return nil
}

func validateDnsmasqConf(s string) error {
	blocked := map[string]bool{
		"dhcp-script": true, "dhcp-luascript": true, "dhcp-scriptuser": true,
		"script-on-renewal": true, "lua-script": true,
		"conf-file": true, "conf-dir": true,
		"servers-file": true, "dhcp-hostsfile": true, "dhcp-optsfile": true,
		"dhcp-hostsdir": true, "dhcp-optsdir": true, "log-facility": true,
		"pid-file": true, "leasefile-ro": true,
	}
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// dnsmasq accepts both "key value" and "key=value".
		directive := fields[0]
		if idx := strings.IndexByte(directive, '='); idx >= 0 {
			directive = directive[:idx]
		}
		if blocked[strings.ToLower(directive)] {
			return fmt.Errorf("SECURITY: dangerous dnsmasq directive: %s", directive)
		}
	}
	return nil
}

func validateWireGuardConf(s string) error {
	allowedPost := map[string]bool{
		"nft add table inet wg-filter": true,
		"nft add chain inet wg-filter postrouting '{ type nat hook postrouting priority 100; policy accept; }'": true,
		// Only the interface-scoped masquerade is allowed. The legacy rule without an
		// interface match rewrote the source of all forwarded traffic and is rejected.
		`nft add rule inet wg-filter postrouting iifname "wg0" oifname != "wg0" masquerade`: true,
		"nft delete table inet wg-filter": true,
	}
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("SECURITY: malformed WireGuard line: %s", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "PreUp", "PreDown", "PostUp", "PostDown":
			if !allowedPost[value] {
				return fmt.Errorf("SECURITY: dangerous WireGuard hook: %s", key)
			}
		}
	}
	return nil
}

func validateOpenVPNFile(path, s string) error {
	if !strings.HasSuffix(path, ".conf") {
		return nil // certificates, keys, auth files
	}
	blocked := map[string]bool{
		"plugin": true, "up": true, "down": true, "route-up": true,
		"route-pre-down": true, "ipchange": true, "learn-address": true,
		"client-connect": true, "client-disconnect": true,
		"auth-user-pass-verify": true, "tls-verify": true,
		"script-security": true, "config": true, "management": true,
		"daemon": true, "chroot": true, "askpass": true,
	}
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		if blocked[directive] {
			return fmt.Errorf("SECURITY: dangerous OpenVPN directive: %s", directive)
		}
		switch directive {
		case "status", "log", "writepid":
			// These write files. Allow only relative, non-traversing paths
			// inside the instance's working directory.
			if len(fields) < 2 {
				return fmt.Errorf("SECURITY: OpenVPN %s requires a path", directive)
			}
			path := fields[1]
			if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
				return fmt.Errorf("SECURITY: OpenVPN %s path must be relative: %s", directive, path)
			}
		case "auth-user-pass":
			if len(fields) >= 2 && strings.HasPrefix(fields[1], "/") && !strings.HasPrefix(fields[1], "/etc/openvpn/") {
				return fmt.Errorf("SECURITY: OpenVPN auth file must be under /etc/openvpn")
			}
		}
	}
	return nil
}

func validateResolvedConf(s string) error {
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line == "[Resolve]" || strings.HasPrefix(line, "DNS=") ||
			strings.HasPrefix(line, "DNSOverTLS=") || strings.HasPrefix(line, "Domains=") {
			continue
		}
		return fmt.Errorf("SECURITY: unexpected resolved directive: %s", line)
	}
	return nil
}

func validateSuricataConf(s string) error {
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "re:") {
			continue
		}
		return fmt.Errorf("SECURITY: unexpected Suricata modify.conf line: %s", line)
	}
	return nil
}

func validateNftablesConf(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("SECURITY: empty nftables ruleset")
	}
	return nil
}

func validateRadvdConf(s string) error {
	blocked := []string{"pre_config", "post_config", "include", "script"}
	for _, raw := range strings.Split(s, "\n") {
		line := strings.ToLower(strings.TrimSpace(raw))
		for _, word := range blocked {
			if strings.Contains(line, word) {
				return fmt.Errorf("SECURITY: dangerous radvd directive: %s", word)
			}
		}
	}
	return nil
}

func validateFRRConf(s string) error {
	// FRR config is applied by the frr user; it cannot execute shell commands.
	return nil
}

func validateMiniupnpdConf(s string) error {
	// miniupnpd config does not contain shell hooks.
	return nil
}

func helperWriteFile(path string, content []byte, mode os.FileMode, appendMode bool) error {
	if err := validateManagedPath(path, false); err != nil {
		return err
	}
	if err := validateManagedContent(path, content); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0644
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	if !appendMode {
		return helperAtomicWrite(path, content, mode)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|os.O_APPEND, mode)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// helperAtomicWrite replaces path with content so that readers (wg-quick, dnsmasq, nft, ...)
// see either the complete old file or the complete new one, never a half-written file. The
// content goes to a hidden temporary file in the same directory, is synced, and is then renamed
// over the target. A symlink at the target is refused, as before.
func helperAtomicWrite(path string, content []byte, mode os.FileMode) error {
	dir, base := filepath.Dir(path), filepath.Base(path)
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink %s", path)
		}
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+base+".softrouter-tmp-*") // O_EXCL, mode 0600
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	if d, err := os.Open(dir); err == nil { // make the rename itself durable
		d.Sync()
		d.Close()
	}
	return nil
}

func helperMkdirDir(path string, mode os.FileMode) error {
	if err := validateManagedPath(path, false); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0755
	}
	return os.MkdirAll(path, mode)
}

func helperRemovePath(path string, recursive bool) error {
	if err := validateManagedPath(path, false); err != nil {
		return err
	}
	if recursive {
		return os.RemoveAll(path)
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func helperRenamePath(oldPath, newPath string) error {
	if err := validateManagedPath(oldPath, false); err != nil {
		return err
	}
	if err := validateManagedPath(newPath, false); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newPath), 0750); err != nil {
		return err
	}
	return os.Rename(oldPath, newPath)
}

func helperCopyPath(src, dst string) error {
	if err := validateManagedPath(src, true); err != nil {
		return err
	}
	if err := validateManagedPath(dst, false); err != nil {
		return err
	}
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SECURITY: refusing to copy a symlink")
	}
	if info.IsDir() {
		return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("SECURITY: refusing to copy symlink %s", path)
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, rel)
			if fi.IsDir() {
				return os.MkdirAll(target, fi.Mode().Perm())
			}
			return helperCopyFile(path, target, fi.Mode().Perm())
		})
	}
	return helperCopyFile(src, dst, info.Mode().Perm())
}

func helperCopyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// maxHelperOutput caps how much output of one command is returned to the backend.
const maxHelperOutput = 8 << 20

// limitedBuffer keeps at most max bytes and silently drops the rest, so a noisy
// command cannot exhaust the helper's memory.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

// validEasyRSAClientName reports whether name may be used as a client certificate name.
// The server and CA material is never a client, and its key must never be readable.
func validEasyRSAClientName(name string) bool {
	if name == "server" || name == "ca" {
		return false
	}
	return validVPNClientName.MatchString(name)
}
