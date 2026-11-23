package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// isRoot reports whether the backend runs as root. It is a variable so tests can simulate the
// unprivileged service account.
var isRoot = func() bool { return os.Getuid() == 0 }

// errHelperUnreachable means the helper could not be contacted at all, so nothing was
// executed and it is safe to fall back to running the command locally.
var errHelperUnreachable = errors.New("privileged helper unreachable")

var (
	helperProbeMu sync.Mutex
	helperProbeAt time.Time
	helperProbeOK bool
)

// privHelperAvailable checks if the privileged helper socket exists.
// The result is cached for two seconds, so a missing helper costs one stat per interval
// and never delays a command.
func privHelperAvailable() bool {
	helperProbeMu.Lock()
	defer helperProbeMu.Unlock()
	if !helperProbeAt.IsZero() && time.Since(helperProbeAt) < 2*time.Second {
		return helperProbeOK
	}
	_, err := os.Stat(privSocketPath)
	helperProbeAt = time.Now()
	helperProbeOK = err == nil
	return helperProbeOK
}

// runViaHelperRequest sends a request to the privileged helper.
func runViaHelperRequest(req PrivRequest) (PrivResponse, error) {
	conn, err := net.DialTimeout("unix", privSocketPath, 5*time.Second)
	if err != nil {
		return PrivResponse{}, fmt.Errorf("%w: %v", errHelperUnreachable, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return PrivResponse{}, fmt.Errorf("failed to send request: %w", err)
	}

	// Commands are limited to 10 minutes by getCommandContext; allow a little longer.
	conn.SetReadDeadline(time.Now().Add(12 * time.Minute))
	var resp PrivResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return PrivResponse{}, fmt.Errorf("failed to read response: %w", err)
	}
	return resp, nil
}

// runViaHelper sends an exec request to the privileged helper.
func runViaHelper(cmd string, args ...string) (string, string, int, error) {
	resp, err := runViaHelperRequest(PrivRequest{Op: "exec", Command: cmd, Args: args})
	if err != nil {
		return "", "", 1, err
	}
	return resp.Stdout, resp.Stderr, resp.ExitCode, nil
}

// runViaHelperInDir sends an exec request with a working directory.
func runViaHelperInDir(dir, cmd string, stdin []byte, args ...string) (string, string, int, error) {
	resp, err := runViaHelperRequest(PrivRequest{
		Op:      "exec",
		Command: cmd,
		Args:    args,
		Dir:     dir,
		Stdin:   stdin,
	})
	if err != nil {
		return "", "", 1, err
	}
	return resp.Stdout, resp.Stderr, resp.ExitCode, nil
}

// runPrivilegedViaHelper executes a privileged command via the helper.
func runPrivilegedViaHelper(cmd string, args ...string) error {
	stdout, stderr, exitCode, err := runViaHelper(cmd, args...)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		if stderr != "" {
			return fmt.Errorf("command '%s' failed (exit %d): %s", cmd, exitCode, stderr)
		}
		if stdout != "" {
			return fmt.Errorf("command '%s' failed (exit %d): %s", cmd, exitCode, stdout)
		}
		return fmt.Errorf("command '%s' failed (exit %d)", cmd, exitCode)
	}
	return nil
}

// runPrivilegedOutputViaHelper executes a privileged command via the helper and returns stdout.
func runPrivilegedOutputViaHelper(cmd string, args ...string) ([]byte, error) {
	stdout, stderr, exitCode, err := runViaHelper(cmd, args...)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		if stderr != "" {
			return []byte(stdout), fmt.Errorf("command '%s' failed (exit %d): %s", cmd, exitCode, stderr)
		}
		return []byte(stdout), fmt.Errorf("command '%s' failed (exit %d)", cmd, exitCode)
	}
	return []byte(stdout), nil
}

func helperFileOp(req PrivRequest) error {
	resp, err := runViaHelperRequest(req)
	if err != nil {
		return err
	}
	if resp.ExitCode != 0 {
		if resp.Stderr != "" {
			return fmt.Errorf("%s", resp.Stderr)
		}
		return fmt.Errorf("privileged %s failed", req.Op)
	}
	return nil
}

// writeManagedFile writes a file through the helper (which enforces path and
// content policy). Falls back to a direct write only when running as root and
// no helper is available, which is useful for development/tests.
func writeManagedFile(path string, content []byte, mode os.FileMode) error {
	req := PrivRequest{Op: "write", Path: path, Content: content, Mode: uint32(mode)}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		return writeManagedFileDirect(path, content, mode, false)
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

func appendManagedFile(path string, content []byte, mode os.FileMode) error {
	req := PrivRequest{Op: "append", Path: path, Content: content, Mode: uint32(mode)}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		return writeManagedFileDirect(path, content, mode, true)
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

func mkdirManagedDir(path string, mode os.FileMode) error {
	req := PrivRequest{Op: "mkdir", Path: path, Mode: uint32(mode)}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		return os.MkdirAll(path, mode)
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

func removeManagedFile(path string) error {
	req := PrivRequest{Op: "remove", Path: path}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

func removeManagedDirAll(path string) error {
	req := PrivRequest{Op: "remove_all", Path: path}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		return os.RemoveAll(path)
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

func renameManagedPath(oldPath, newPath string) error {
	req := PrivRequest{Op: "rename", Path: oldPath, NewPath: newPath}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		return os.Rename(oldPath, newPath)
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

func copyManagedPath(src, dst string) error {
	req := PrivRequest{Op: "copy", Path: src, NewPath: dst}
	if privHelperAvailable() {
		return helperFileOp(req)
	}
	if isRoot() {
		return copyPathDirect(src, dst)
	}
	return fmt.Errorf("privileged helper unavailable and process is not root")
}

// readManagedFile reads a PKI file through the helper. The helper enforces a
// strict read allowlist; this does not grant access to arbitrary root files.
func readManagedFile(path string) ([]byte, error) {
	if privHelperAvailable() {
		resp, err := runViaHelperRequest(PrivRequest{Op: "read", Path: path})
		if err != nil {
			return nil, err
		}
		if resp.ExitCode == 2 {
			return nil, &os.PathError{Op: "read", Path: path, Err: syscall.ENOENT} // os.IsNotExist works
		}
		if resp.ExitCode != 0 {
			if resp.Stderr != "" {
				return nil, fmt.Errorf("%s", resp.Stderr)
			}
			return nil, fmt.Errorf("privileged read failed")
		}
		return resp.Data, nil
	}
	if isRoot() {
		if err := validateManagedReadPath(path); err != nil {
			return nil, err
		}
		return os.ReadFile(path)
	}
	return nil, fmt.Errorf("privileged helper unavailable and process is not root")
}

// Direct fallbacks are used only when running as root without the helper
// (development and recovery). They apply the same policy checks.
func writeManagedFileDirect(path string, content []byte, mode os.FileMode, appendMode bool) error {
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
	flags := os.O_WRONLY | os.O_CREATE | syscall.O_NOFOLLOW
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, mode)
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

func copyPathDirect(src, dst string) error {
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
	if info.IsDir() {
		return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, rel)
			if fi.IsDir() {
				return os.MkdirAll(target, fi.Mode().Perm())
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, fi.Mode().Perm())
		})
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

// managedPathExists reports whether a managed config file exists. Root checks directly; the
// unprivileged backend asks the helper, because directories such as /etc/wireguard are not
// traversable by its user.
func managedPathExists(path string) (bool, error) {
	if isRoot() {
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !privHelperAvailable() {
		return false, errHelperRequired
	}
	resp, err := runViaHelperRequest(PrivRequest{Op: "exists", Path: path})
	if err != nil {
		return false, err
	}
	if resp.ExitCode != 0 {
		return false, fmt.Errorf("%s", resp.Stderr)
	}
	return resp.Stdout == "yes", nil
}
