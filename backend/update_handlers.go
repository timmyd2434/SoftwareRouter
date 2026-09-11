package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type UpdateStatus struct {
	CurrentBranch   string `json:"current_branch"`
	CurrentCommit   string `json:"current_commit"`
	LatestCommit    string `json:"latest_commit"`
	UpdateAvailable bool   `json:"update_available"`
	BehindCount     int    `json:"behind_count"`
	LastChecked     string `json:"last_checked"`
}

func getRepoDir() string {
	// Primary: read the path written by update.sh / install.sh.
	// This is the only reliable method when the binary is running as a
	// systemd service (WorkingDirectory=/usr/local/bin) on a machine where
	// the repo may be cloned anywhere (not necessarily /home/tim/...).
	if data, err := os.ReadFile("/etc/softrouter/repo_path"); err == nil {
		p := strings.TrimSpace(string(data))
		if p != "" {
			if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
				return p
			}
			// Path recorded but .git not found there — log and fall through
			log.Printf("[UPDATE] /etc/softrouter/repo_path points to %q but no .git found there", p)
		}
	}

	// Secondary: cwd or its parent (works when running manually from the repo).
	if cwd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(cwd, ".git")); err == nil {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if _, err := os.Stat(filepath.Join(parent, ".git")); err == nil {
			return parent
		}
	}

	// Tertiary: well-known install paths.
	for _, candidate := range []string{
		"/opt/SoftwareRouter",
		"/opt/softrouter",
		"/srv/SoftwareRouter",
	} {
		if _, err := os.Stat(filepath.Join(candidate, ".git")); err == nil {
			return candidate
		}
	}

	// No repo found — return empty so callers can surface a clear error.
	log.Printf("[UPDATE] WARNING: could not locate repo directory. Run update.sh once to persist the path.")
	return ""
}

func getUpdateStatus(w http.ResponseWriter, r *http.Request) {
	repoDir := getRepoDir()
	branch := r.URL.Query().Get("branch")

	if repoDir == "" {
		respondSystemError(w, ErrGenericInternalError,
			"Repo directory not found. Run update.sh once to register the repo path.", nil)
		return
	}

	if branch == "" {
		branch = "Dev" // default
	}
	if branch != "main" && branch != "Dev" {
		respondInvalidRequest(w, "Branch must be 'main' or 'Dev'")
		return
	}

	// runGit runs a git command safely
	runGit := func(args ...string) ([]byte, error) {
		gitArgs := append([]string{"-c", "safe.directory=*", "-C", repoDir}, args...)
		cmd := exec.Command("git", gitArgs...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0", // never prompt for credentials
		)
		return cmd.Output()
	}

	runGitCombined := func(args ...string) ([]byte, error) {
		gitArgs := append([]string{"-c", "safe.directory=*", "-C", repoDir}, args...)
		cmd := exec.Command("git", gitArgs...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
		)
		return cmd.CombinedOutput()
	}

	// Fetch latest from origin (non-fatal — display cached data if it fails)
	if out, err := runGitCombined("fetch", "origin"); err != nil {
		log.Printf("[WARN] git fetch origin failed (%v): %s — trying HTTPS...", err, strings.TrimSpace(string(out)))
		refSpec := fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", branch, branch)
		if out2, err2 := runGitCombined("fetch", "https://github.com/timmyd2434/SoftwareRouter.git", refSpec); err2 != nil {
			log.Printf("[WARN] HTTPS fetch also failed: %v: %s", err2, strings.TrimSpace(string(out2)))
		}
	}

	// Current branch
	currBranchOut, _ := runGit("branch", "--show-current")
	currentBranch := strings.TrimSpace(string(currBranchOut))
	if currentBranch == "" {
		currentBranch = branch
	}

	// Current (installed) commit
	currCommitOut, err := runGit("rev-parse", "--short", "HEAD")
	currentCommit := strings.TrimSpace(string(currCommitOut))
	if err != nil {
		log.Printf("[WARN] git rev-parse HEAD failed in %s: %v", repoDir, err)
	}

	// Latest commit on the remote branch
	latestCommitOut, err := runGit("rev-parse", "--short", "origin/"+branch)
	latestCommit := strings.TrimSpace(string(latestCommitOut))
	if latestCommit == "" || err != nil {
		// Fallback: use FETCH_HEAD written by the fetch above
		fetchHeadOut, _ := runGit("rev-parse", "--short", "FETCH_HEAD")
		latestCommit = strings.TrimSpace(string(fetchHeadOut))
		if latestCommit == "" {
			log.Printf("[WARN] Could not resolve origin/%s or FETCH_HEAD in %s", branch, repoDir)
		}
	}

	// How many commits is HEAD behind the remote?
	targetRef := "origin/" + branch
	checkRefOut, checkErr := runGit("rev-parse", "--verify", targetRef)
	if checkErr != nil || strings.TrimSpace(string(checkRefOut)) == "" {
		targetRef = "FETCH_HEAD"
	}
	behindOut, _ := runGit("rev-list", "--count", "HEAD.."+targetRef)
	behindCount, _ := strconv.Atoi(strings.TrimSpace(string(behindOut)))

	status := UpdateStatus{
		CurrentBranch:   currentBranch,
		CurrentCommit:   currentCommit,
		LatestCommit:    latestCommit,
		UpdateAvailable: behindCount > 0,
		BehindCount:     behindCount,
		LastChecked:     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func applyUpdate(w http.ResponseWriter, r *http.Request) {
	repoDir := getRepoDir()
	var req struct {
		Branch string `json:"branch"`
		Force  bool   `json:"force"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondInvalidRequest(w, "Invalid request body")
		return
	}

	if repoDir == "" {
		respondSystemError(w, ErrGenericInternalError,
			"Repo directory not found. Run update.sh once to register the repo path.", nil)
		return
	}

	if req.Branch != "main" && req.Branch != "Dev" {
		respondInvalidRequest(w, "Branch must be 'main' or 'Dev'")
		return
	}

	var args []string
	args = append(args, "--branch", req.Branch)
	if req.Force {
		args = append(args, "--force")
	}

	logAuditEvent(getUsernameFromToken(r), "system.update", "system", fmt.Sprintf("{\"branch\":\"%s\",\"force\":%v}", req.Branch, req.Force), getClientIP(r), true)

	updateScript := filepath.Join(repoDir, "update.sh")
	go func() {
		var output []byte
		var err error
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			homeDir = "/root"
		}
		pathEnv := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		if curPath := os.Getenv("PATH"); curPath != "" {
			pathEnv += ":" + curPath
		}

		if os.Getuid() == 0 {
			// Run via systemd-run in isolated transient unit so stopping softrouter doesn't kill the update script
			unitName := fmt.Sprintf("softrouter-update-%d", time.Now().Unix())
			sysdArgs := []string{
				"--unit=" + unitName,
				"--no-block",          // fire-and-forget: don't wait for the unit to finish
				"--service-type=oneshot",
				"-p", "WorkingDirectory=" + repoDir,
				"-p", "Environment=PATH=" + pathEnv,
				"-p", "Environment=HOME=" + homeDir,
				"-p", "Environment=GOCACHE=/tmp/go-build-cache",
				"-p", "Environment=GOPATH=/tmp/go",
				updateScript,
			}
			sysdArgs = append(sysdArgs, args...)
			output, err = runPrivilegedCombinedOutput("systemd-run", sysdArgs...)
		} else {
			output, err = runPrivilegedInDirCombinedOutput(repoDir, updateScript, args...)
		}
		if err != nil {
			log.Printf("[ERROR] Update execution failed: %v\nOutput: %s", err, string(output))
		} else {
			log.Printf("[INFO] Update process launched: %s", string(output))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updating",
		"message": "Update initiated. The system will restart momentarily.",
	})
}
