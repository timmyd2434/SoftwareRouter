package main

import (
	"errors"
	"fmt"
	"strings"
)

// tryHelperExec runs a command through the privileged helper when it is running.
// used=false means the helper could not be contacted (nothing was executed) and the
// caller should run the command locally, exactly as before. Once the helper has
// accepted a request there is never a local retry, so a command cannot run twice.
func tryHelperExec(dir string, stdin []byte, combined bool, cmd string, args ...string) (out []byte, err error, used bool) {
	if !privHelperAvailable() {
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
