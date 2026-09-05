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
	if cwd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(cwd, ".git")); err == nil {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if _, err := os.Stat(filepath.Join(parent, ".git")); err == nil {
			return parent
		}
	}
	if _, err := os.Stat("/opt/SoftwareRouter/.git"); err == nil {
		return "/opt/SoftwareRouter"
	}
	return "/home/tim/SoftwareRouter/SoftwareRouter"
}

func getUpdateStatus(w http.ResponseWriter, r *http.Request) {
	repoDir := getRepoDir()
	branch := r.URL.Query().Get("branch")

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
		if out2, err2 := runGitCombined("fetch", "https://github.com/timmyd2434/SoftwareRouter.git", branch); err2 != nil {
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
		if os.Getuid() == 0 {
			// Run via systemd-run in isolated transient unit so stopping softrouter doesn't kill the update script
			unitName := fmt.Sprintf("softrouter-update-%d", time.Now().Unix())
			sysdArgs := append([]string{"--unit=" + unitName, "--service-type=oneshot", updateScript}, args...)
			output, err = runPrivilegedCombinedOutput("systemd-run", sysdArgs...)
		} else {
			output, err = runPrivilegedInDirCombinedOutput(repoDir, updateScript, args...)
		}
		if err != nil {
			log.Printf("[ERROR] Update execution failed: %v\nOutput: %s", err, string(output))
		} else {
			log.Printf("[INFO] Update process completed successfully: %s", string(output))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updating",
		"message": "Update initiated. The system will restart momentarily.",
	})
}
