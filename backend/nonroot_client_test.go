package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// asUnprivileged makes the backend believe it is not root, and outside a test binary, for one test.
func asUnprivileged(t *testing.T) {
	t.Helper()
	oldRoot, oldTest := isRoot, inTestBinary
	isRoot = func() bool { return false }
	inTestBinary = func() bool { return false }
	t.Cleanup(func() { isRoot, inTestBinary = oldRoot, oldTest })
}

func noHelperRunning(t *testing.T) {
	t.Helper()
	old, oldAt := privSocketPath, helperProbeAt
	privSocketPath = filepath.Join(t.TempDir(), "missing.sock")
	helperProbeAt = helperProbeAt.Add(-time3600)
	t.Cleanup(func() { privSocketPath, helperProbeAt = old, oldAt })
}

func TestUnprivilegedBackendNeverFallsBackToSudo(t *testing.T) {
	asUnprivileged(t)
	noHelperRunning(t)
	err := runPrivileged("ip", "addr", "show", "lo")
	if !errors.Is(err, errHelperRequired) {
		t.Fatalf("expected errHelperRequired, got %v", err)
	}
	if _, err := runPrivilegedOutput("ip", "addr", "show", "lo"); !errors.Is(err, errHelperRequired) {
		t.Errorf("Output variant: %v", err)
	}
	if _, err := runPrivilegedCombinedOutput("ip", "addr", "show", "lo"); !errors.Is(err, errHelperRequired) {
		t.Errorf("CombinedOutput variant: %v", err)
	}
	if err := runPrivilegedInDir("/etc/openvpn/easy-rsa", "openvpn", "--version"); !errors.Is(err, errHelperRequired) {
		t.Errorf("InDir variant: %v", err)
	}
}

func TestUnprivilegedFileAccessGoesThroughTheHelper(t *testing.T) {
	asUnprivileged(t)
	reqs := serveFakeHelper(t, PrivResponse{Stdout: "yes", Data: []byte("[Interface]\n")})

	ok, err := managedPathExists("/etc/wireguard/wg0.conf")
	if err != nil || !ok {
		t.Fatalf("exists: %v %v", ok, err)
	}
	if r := <-reqs; r.Op != "exists" || r.Path != "/etc/wireguard/wg0.conf" {
		t.Errorf("unexpected request %+v", r)
	}
	data, err := readManagedFile("/etc/wireguard/wg0.conf")
	if err != nil || string(data) != "[Interface]\n" {
		t.Fatalf("read: %q %v", data, err)
	}
	if r := <-reqs; r.Op != "read" {
		t.Errorf("unexpected request %+v", r)
	}
	if err := writeRootConfig("/etc/wireguard/wg0.conf", []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := <-reqs; r.Op != "write" || string(r.Content) != "x" {
		t.Errorf("a root-interpreted config must be written by the helper: %+v", r)
	}
}

func TestUnprivilegedExistsAndReadReportMissingFiles(t *testing.T) {
	asUnprivileged(t)
	serveFakeHelper(t, PrivResponse{Stdout: "no"})
	if ok, err := managedPathExists("/etc/wireguard/wg0.conf"); err != nil || ok {
		t.Errorf("a missing file should be (false, nil), got %v %v", ok, err)
	}

	serveFakeHelper(t, PrivResponse{ExitCode: 2, Stderr: "no such file"})
	_, err := readManagedFile("/etc/openvpn/easy-rsa/pki/index.txt")
	if !os.IsNotExist(err) {
		t.Errorf("a missing file must satisfy os.IsNotExist, got %v", err)
	}
}

func TestUnprivilegedExistsWithoutHelperIsAnError(t *testing.T) {
	asUnprivileged(t)
	noHelperRunning(t)
	if _, err := managedPathExists("/etc/wireguard/wg0.conf"); !errors.Is(err, errHelperRequired) {
		t.Errorf("expected errHelperRequired, got %v", err)
	}
	// With the answer unknown, WireGuard rules are not emitted on a guess.
	if (Config{}).WireGuardEnabled() {
		t.Error("an unknown answer must not enable WireGuard rules")
	}
}

func TestHelperExistsAndReadOperations(t *testing.T) {
	// Disallowed paths are refused, whatever the caller asks.
	r := handlePrivRequest(PrivRequest{Op: "exists", Path: "/etc/shadow"})
	if r.ExitCode == 0 {
		t.Error("exists must refuse paths outside the managed list")
	}
	r = handlePrivRequest(PrivRequest{Op: "exists", Path: "/etc/wireguard/wg0.conf"})
	if r.ExitCode != 0 || (r.Stdout != "yes" && r.Stdout != "no") {
		t.Errorf("exists on a managed path should answer yes or no: %+v", r)
	}
	// A managed file that does not exist reads as "not found" (exit 2), not as an error.
	if _, err := os.Stat("/etc/openvpn/easy-rsa/pki/index.txt"); os.IsNotExist(err) {
		r = handlePrivRequest(PrivRequest{Op: "read", Path: "/etc/openvpn/easy-rsa/pki/index.txt"})
		if r.ExitCode != 2 {
			t.Errorf("a missing file should be exit 2, got %+v", r)
		}
	}
	if err := validateManagedReadPath("/etc/wireguard/wg0.conf"); err != nil {
		t.Errorf("wg0.conf must be readable through the helper: %v", err)
	}
	if err := validateManagedReadPath("/etc/wireguard/other.conf"); err == nil {
		t.Error("other WireGuard files must not be readable")
	}
}

func TestRemoteBranchHeadParsing(t *testing.T) {
	const a = "0123456789abcdef0123456789abcdef01234567"
	const b = "fedcba9876543210fedcba9876543210fedcba98"
	out := a + "\trefs/heads/Dev\n" + b + "\trefs/heads/main\n"
	if got := remoteBranchHead(out, "Dev"); got != a {
		t.Errorf("Dev = %q", got)
	}
	if got := remoteBranchHead(out, "main"); got != b {
		t.Errorf("main = %q", got)
	}
	for _, bad := range []string{"", "garbage", "zzzz\trefs/heads/Dev", a[:39] + "\trefs/heads/Dev", a + "\trefs/heads/Dev2"} {
		if got := remoteBranchHead(bad, "Dev"); got != "" {
			t.Errorf("%q should not parse, got %q", bad, got)
		}
	}
	if shortCommit(a) != "0123456" {
		t.Errorf("shortCommit = %q", shortCommit(a))
	}
}

func TestReadOnlyRemoteHeadFallsBackToHTTPS(t *testing.T) {
	const h = "0123456789abcdef0123456789abcdef01234567"
	var calls []string
	runGit := func(args ...string) ([]byte, error) {
		calls = append(calls, args[1])
		if args[1] == "origin" {
			return nil, errors.New("ssh: no keys")
		}
		return []byte(h + "\trefs/heads/Dev\n"), nil
	}
	if got := readOnlyRemoteHead(runGit, "Dev"); got != h {
		t.Errorf("got %q (calls %v)", got, calls)
	}
	if len(calls) != 2 || calls[0] != "origin" {
		t.Errorf("expected origin first, then HTTPS: %v", calls)
	}
}
