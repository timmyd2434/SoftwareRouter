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
		// get current branch
		cmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "branch", "--show-current")
		out, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			branch = strings.TrimSpace(string(out))
		} else {
			branch = "Dev" // fallback
		}
	}

	if branch != "main" && branch != "Dev" {
		respondInvalidRequest(w, "Branch must be 'main' or 'Dev'")
		return
	}

	// Fix .git directory permissions before fetching.
	// The service runs as root but the repo may be owned by the original user (e.g. tim).
	// git refuses to write FETCH_HEAD if it can't open the file.
	// Make the .git directory and all files group-readable/writable so any user can fetch.
	gitDir := filepath.Join(repoDir, ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		// chmod -R a+rw .git — ignore errors (best-effort)
		_ = exec.Command("chmod", "-R", "a+rw", gitDir).Run()
	}

	// Determine who owns the repo so we can run git as that user
	repoOwner := ""
	if info, err := os.Stat(repoDir); err == nil {
		// Try to get the owning username via stat
		statCmd := exec.Command("stat", "-c", "%U", repoDir)
		if out, err := statCmd.Output(); err == nil {
			owner := strings.TrimSpace(string(out))
			if owner != "" && owner != "root" {
				repoOwner = owner
			}
		}
		_ = info
	}

	// Run a git command, either as repo owner (if different from current user) or directly
	runGit := func(args ...string) ([]byte, error) {
		baseArgs := append([]string{"-c", "safe.directory=*", "-C", repoDir}, args...)
		if repoOwner != "" && os.Getuid() == 0 {
			suArgs := append([]string{"-u", repoOwner, "git"}, baseArgs...)
			cmd := exec.Command("sudo", suArgs...)
			return cmd.Output()
		}
		return exec.Command("git", baseArgs...).Output()
	}

	runGitCombined := func(args ...string) ([]byte, error) {
		baseArgs := append([]string{"-c", "safe.directory=*", "-C", repoDir}, args...)
		if repoOwner != "" && os.Getuid() == 0 {
			suArgs := append([]string{"-u", repoOwner, "git"}, baseArgs...)
			cmd := exec.Command("sudo", suArgs...)
			return cmd.CombinedOutput()
		}
		cmd := exec.Command("git", baseArgs...)
		return cmd.CombinedOutput()
	}

	// Fetch latest from origin
	if out, err := runGitCombined("fetch", "origin"); err != nil {
		log.Printf("[WARN] Failed to fetch git updates from origin (%v): %s. Attempting HTTPS fetch...", err, string(out))
		if out2, err2 := runGitCombined("fetch", "https://github.com/timmyd2434/SoftwareRouter.git", branch); err2 != nil {
			log.Printf("[WARN] HTTPS fetch failed: %v, output: %s", err2, string(out2))
		}
	}

	// Current branch
	currBranchOut, _ := runGit("branch", "--show-current")
	currentBranch := strings.TrimSpace(string(currBranchOut))
	if currentBranch == "" {
		currentBranch = branch
	}

	// Current commit
	currCommitOut, _ := runGit("rev-parse", "--short", "HEAD")
	currentCommit := strings.TrimSpace(string(currCommitOut))

	// Latest commit on remote branch
	latestCommitOut, err := runGit("rev-parse", "--short", "origin/"+branch)
	latestCommit := strings.TrimSpace(string(latestCommitOut))
	if latestCommit == "" || err != nil {
		fetchHeadOut, _ := runGit("rev-parse", "--short", "FETCH_HEAD")
		latestCommit = strings.TrimSpace(string(fetchHeadOut))
	}

	// Behind count
	targetRef := "origin/" + branch
	if latestCommit != "" {
		checkRefOut, checkErr := runGit("rev-parse", "--verify", targetRef)
		if checkErr != nil || strings.TrimSpace(string(checkRefOut)) == "" {
			targetRef = "FETCH_HEAD"
		}
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
		var cmd *exec.Cmd
		if os.Getuid() == 0 {
			// Run via systemd-run in isolated transient unit so stopping softrouter doesn't kill the update script
			unitName := fmt.Sprintf("softrouter-update-%d", time.Now().Unix())
			sysdArgs := append([]string{"--unit=" + unitName, "--service-type=oneshot", updateScript}, args...)
			cmd = exec.Command("systemd-run", sysdArgs...)
		} else {
			cmd = exec.Command("sudo", append([]string{"-n", updateScript}, args...)...)
		}
		cmd.Dir = repoDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] Update launch failed: %v\nOutput: %s. Retrying directly with nohup...", err, string(output))
			fallbackCmd := exec.Command("nohup", append([]string{"bash", updateScript}, args...)...)
			fallbackCmd.Dir = repoDir
			_ = fallbackCmd.Start()
		} else {
			log.Printf("[INFO] Update process launched successfully: %s", string(output))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updating",
		"message": "Update initiated. The system will restart momentarily.",
	})
}
