package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

// errHelperRequired is returned when the backend runs without root and the privileged helper is
// not available. The backend never falls back to sudo, so the failure is explicit and immediate.
var errHelperRequired = errors.New("the privileged helper (softrouter-privhelper.service) is not running, and the backend is not root")

// inTestBinary reports whether this is a "go test" binary; tests keep running commands locally.
var inTestBinary = func() bool { return flag.Lookup("test.v") != nil }

// tryHelperExec runs a command through the privileged helper when it is running.
// used=false means the helper could not be contacted (nothing was executed) and the
// caller should run the command locally, exactly as before. Once the helper has
// accepted a request there is never a local retry, so a command cannot run twice.
func tryHelperExec(dir string, stdin []byte, combined bool, cmd string, args ...string) (out []byte, err error, used bool) {
	if !privHelperAvailable() {
		if !isRoot() && !inTestBinary() {
			return nil, errHelperRequired, true
		}
		return nil, nil, false
	}
	resp, rerr := runViaHelperRequest(PrivRequest{
		Op: "exec", Command: cmd, Args: args, Dir: dir, Stdin: stdin, Combined: combined,
	})
	if rerr != nil {
		if errors.Is(rerr, errHelperUnreachable) {
			return nil, nil, false
		}
		return nil, rerr, true
	}
	out = []byte(resp.Stdout)
	if resp.ExitCode != 0 {
		msg := fmt.Sprintf("exit status %d", resp.ExitCode)
		if e := strings.TrimSpace(resp.Stderr); e != "" {
			msg += ": " + e
		}
		return out, errors.New(msg), true
	}
	return out, nil, true
}
