package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nonrootEnv builds a sandbox with fake systemctl/journalctl/ps/... so the cutover script's real
// logic can be exercised without systemd or root.
type nonrootEnv struct {
	t     *testing.T
	dir   string
	state string
	env   []string
}

func newNonrootEnv(t *testing.T) *nonrootEnv {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	state := filepath.Join(dir, "state")
	os.MkdirAll(bin, 0755)
	os.MkdirAll(state, 0755)
	systemd := filepath.Join(dir, "systemd")
	os.MkdirAll(systemd, 0755)

	shim := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	shim("systemctl", `
case "$1" in
  is-active)
    shift; [ "$1" = "--quiet" ] && shift
    if [ -f "$SHIM_STATE/inactive-$1" ]; then echo inactive; exit 3; fi
    echo active; exit 0;;
  show)
    case "$3" in
      User) [ -f "$SR_SYSTEMD_DIR/softrouter.service.d/10-nonroot.conf" ] && echo softrouter;;
      MainPID) echo 4242;;
    esac
    exit 0;;
  *) echo "systemctl $*" >> "$SHIM_STATE/calls"; exit 0;;
esac`)
	shim("ps", `cat "$SHIM_STATE/psuser" 2>/dev/null || echo softrouter`)
	shim("journalctl", `
args="$*"
case "$args" in
  *"3 days ago"*) cat "$SHIM_STATE/shadow" 2>/dev/null;;
  *"-u softrouter-privhelper"*) [ -f "$SHIM_STATE/nohelperlog" ] || echo "[PRIVHELPER] systemctl is-active x -> exit 0";;
  *"-u softrouter --since -30s"*) cat "$SHIM_STATE/svclog" 2>/dev/null;;
esac
exit 0`)
	shim("sleep", `exit 0`)
	shim("id", `if [ "$1" = "-u" ] && [ -z "$2" ]; then echo 0; else exit 0; fi`)
	for _, n := range []string{"getent", "groupadd", "useradd", "chown"} {
		shim(n, `echo "`+n+` $*" >> "$SHIM_STATE/calls"; exit 0`)
	}

	// The helper socket must be a real socket for "[ -S ... ]".
	// Unix socket paths are limited to about 100 bytes, so use a short directory.
	sockDir, err := os.MkdirTemp("", "srn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot create a unix socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, "systemd"), 0755)
	dropin, err := os.ReadFile("../systemd/softrouter-nonroot.conf")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(repo, "systemd", "softrouter-nonroot.conf"), dropin, 0644)

	appDirs := []string{filepath.Join(dir, "etc-softrouter"), filepath.Join(dir, "log")}
	return &nonrootEnv{t: t, dir: dir, state: state, env: append(os.Environ(),
		"PATH="+bin+":/usr/bin:/bin",
		"SHIM_STATE="+state,
		"SR_SYSTEMD_DIR="+systemd,
		"SR_SOCKET="+sock,
		"SR_REPO="+repo,
		"SR_APP_DIRS="+strings.Join(appDirs, " "),
	)}
}

func (e *nonrootEnv) run(args ...string) (string, int) {
	cmd := exec.Command("bash", append([]string{"../scripts/softrouter-nonroot"}, args...)...)
	cmd.Env = e.env
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return string(out), code
}

func (e *nonrootEnv) set(name, content string) {
	os.WriteFile(filepath.Join(e.state, name), []byte(content), 0644)
}

func (e *nonrootEnv) dropinExists() bool {
	_, err := os.Stat(filepath.Join(e.dir, "systemd", "softrouter.service.d", "10-nonroot.conf"))
	return err == nil
}

func TestNonrootDryRunChangesNothing(t *testing.T) {
	e := newNonrootEnv(t)
	out, code := e.run("apply", "--dry-run")
	if code != 0 || !strings.Contains(out, "[dry-run]") || !strings.Contains(out, "nothing changed") {
		t.Fatalf("dry run: code=%d\n%s", code, out)
	}
	if e.dropinExists() {
		t.Error("a dry run must not install the drop-in")
	}
}

func TestNonrootRefusesWithoutHelper(t *testing.T) {
	e := newNonrootEnv(t)
	e.set("inactive-softrouter-privhelper", "")
	out, code := e.run("apply")
	if code == 0 || !strings.Contains(out, "softrouter-privhelper is not running") {
		t.Fatalf("expected a refusal, code=%d\n%s", code, out)
	}
	if e.dropinExists() {
		t.Error("nothing may be installed when the helper is down")
	}
}

func TestNonrootRefusesWhileShadowWarningsExist(t *testing.T) {
	e := newNonrootEnv(t)
	e.set("shadow", "Nov 22 [PRIVHELPER-SHADOW] the helper would refuse this content for /etc/x\n")
	out, code := e.run("apply")
	if code == 0 || !strings.Contains(out, "PRIVHELPER-SHADOW") || e.dropinExists() {
		t.Fatalf("expected a refusal without --force, code=%d\n%s", code, out)
	}
	out, code = e.run("apply", "--force")
	if code != 0 || !e.dropinExists() {
		t.Fatalf("--force should proceed, code=%d\n%s", code, out)
	}
}

func TestNonrootApplyAndRollbackHappyPath(t *testing.T) {
	e := newNonrootEnv(t)
	out, code := e.run("apply")
	if code != 0 || !strings.Contains(out, "running as softrouter") || !e.dropinExists() {
		t.Fatalf("apply failed: code=%d\n%s", code, out)
	}
	calls, _ := os.ReadFile(filepath.Join(e.state, "calls"))
	for _, want := range []string{"daemon-reload", "restart softrouter-privhelper", "restart softrouter", "chown -R softrouter:softrouter"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("expected the script to run %q; calls:\n%s", want, calls)
		}
	}
	if out, _ := e.run("apply"); !strings.Contains(out, "already applied") {
		t.Errorf("a second apply should be a no-op:\n%s", out)
	}
	if out, code := e.run("rollback"); code != 0 || e.dropinExists() {
		t.Fatalf("rollback failed: code=%d\n%s", code, out)
	}
}

func TestNonrootRollsBackByItselfWhenVerificationFails(t *testing.T) {
	cases := map[string]func(*nonrootEnv){
		"still running as root": func(e *nonrootEnv) { e.set("psuser", "root\n") },
		"backend cannot reach the helper": func(e *nonrootEnv) {
			e.set("svclog", "privileged helper (softrouter-privhelper.service) is not running, and the backend is not root\n")
		},
		"nothing reaches the helper": func(e *nonrootEnv) { e.set("nohelperlog", "") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e := newNonrootEnv(t)
			setup(e)
			out, code := e.run("apply")
			if code == 0 || !strings.Contains(out, "rolling back") {
				t.Fatalf("expected failure and rollback, code=%d\n%s", code, out)
			}
			if e.dropinExists() {
				t.Error("the drop-in must be removed after a failed verification")
			}
		})
	}
}

// The state directories the script hands over must be writable under ProtectSystem=strict.
func TestDropInCoversTheStateDirectoriesTheScriptChowns(t *testing.T) {
	script, _ := os.ReadFile("../scripts/softrouter-nonroot")
	dropin, _ := os.ReadFile("../systemd/softrouter-nonroot.conf")
	m := regexp.MustCompile(`(?m)^APP_DIRS=\(([^)]*)\)`).FindStringSubmatch(string(script))
	if m == nil {
		t.Fatal("APP_DIRS not found in the script")
	}
	rw := regexp.MustCompile(`(?m)^ReadWritePaths=(.*)$`).FindStringSubmatch(string(dropin))
	if rw == nil {
		t.Fatal("ReadWritePaths not found in the drop-in")
	}
	for _, d := range strings.Fields(m[1]) {
		if !strings.Contains(" "+rw[1]+" ", " -"+d+" ") && !strings.Contains(" "+rw[1]+" ", " "+d+" ") {
			t.Errorf("%s is handed to the service but is not in ReadWritePaths", d)
		}
	}
	for _, want := range []string{"User=softrouter", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "AmbientCapabilities=CAP_NET_BIND_SERVICE"} {
		if !strings.Contains(string(dropin), "\n"+want+"\n") {
			t.Errorf("drop-in is missing %s", want)
		}
	}
	for _, bad := range []string{"CAP_NET_ADMIN", "CAP_SYS_MODULE", "CAP_NET_RAW", "CAP_SYS_ADMIN"} {
		// the only place these may appear is in comments
		for _, line := range strings.Split(string(dropin), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, bad) {
				t.Errorf("drop-in must not grant %s: %s", bad, line)
			}
		}
	}
}

// In non-root mode update.sh must never start a root copy of the backend by hand: that would
// silently undo the cutover (and fight the real service for its ports).
func TestUpdateScriptNeverStartsARootBackendInNonrootMode(t *testing.T) {
	src, err := os.ReadFile("../update.sh")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(src), "\n")
	found := 0
	for i, line := range lines {
		if !strings.Contains(line, "nohup") || !strings.Contains(line, "softrouter-backend") {
			continue
		}
		found++
		start := i - 8
		if start < 0 {
			start = 0
		}
		context := strings.Join(lines[start:i+1], "\n")
		if !strings.Contains(context, "nonroot_applied") && !strings.Contains(context, "systemd service not found") {
			t.Errorf("update.sh line %d starts the backend by hand without checking for non-root mode:\n%s", i+1, line)
		}
	}
	if found == 0 {
		t.Error("expected update.sh to contain its fallback start commands")
	}
	if !strings.Contains(string(src), "fix_state_ownership") {
		t.Error("update.sh must restore ownership of the service's directories after an update")
	}
}
