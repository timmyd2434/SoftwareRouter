package main

import (
	"strings"
)

// The update check normally runs "git fetch" so it can count how far behind HEAD is. When the
// backend is not root, the repository belongs to another user and the service cannot write into
// it, so it asks the remote directly with the read-only "git ls-remote" instead.

// remoteBranchHead extracts the commit id of refs/heads/<branch> from "git ls-remote" output.
func remoteBranchHead(out, branch string) string {
	want := "refs/heads/" + branch
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == want && isFullCommitID(f[0]) {
			return f[0]
		}
	}
	return ""
}

// isFullCommitID reports whether s is a full SHA-1 (40) or SHA-256 (64) hex object id.
func isFullCommitID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func shortCommit(full string) string {
	if len(full) > 7 {
		return full[:7]
	}
	return full
}

// readOnlyRemoteHead returns the newest commit id of a branch without modifying the repository.
func readOnlyRemoteHead(runGit func(args ...string) ([]byte, error), branch string) string {
	ref := "refs/heads/" + branch
	if out, err := runGit("ls-remote", "origin", ref); err == nil {
		if h := remoteBranchHead(string(out), branch); h != "" {
			return h
		}
	}
	// Same HTTPS fallback the fetch path uses when the configured remote is unreachable.
	if out, err := runGit("ls-remote", "https://github.com/timmyd2434/SoftwareRouter.git", ref); err == nil {
		return remoteBranchHead(string(out), branch)
	}
	return ""
}
