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

	// Fetch latest from origin, falling back to public HTTPS if SSH fails
	fetchCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "fetch", "origin")
	if out, err := fetchCmd.CombinedOutput(); err != nil {
		log.Printf("[WARN] Failed to fetch git updates from origin (%v): %s. Attempting HTTPS fetch...", err, string(out))
		httpsFetch := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "fetch", "https://github.com/timmyd2434/SoftwareRouter.git", branch)
		if out2, err2 := httpsFetch.CombinedOutput(); err2 != nil {
			log.Printf("[WARN] HTTPS fetch failed: %v, output: %s", err2, string(out2))
		}
	}

	// Current branch
	currBranchCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "branch", "--show-current")
	currBranchOut, _ := currBranchCmd.Output()
	currentBranch := strings.TrimSpace(string(currBranchOut))
	if currentBranch == "" {
		currentBranch = branch
	}

	// Current commit
	currCommitCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "rev-parse", "--short", "HEAD")
	currCommitOut, _ := currCommitCmd.Output()
	currentCommit := strings.TrimSpace(string(currCommitOut))

	// Latest commit
	latestCommitCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "rev-parse", "--short", "origin/"+branch)
	latestCommitOut, _ := latestCommitCmd.Output()
	latestCommit := strings.TrimSpace(string(latestCommitOut))
	if latestCommit == "" {
		fetchHeadCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "rev-parse", "--short", "FETCH_HEAD")
		fetchHeadOut, _ := fetchHeadCmd.Output()
		latestCommit = strings.TrimSpace(string(fetchHeadOut))
	}

	// Behind count
	targetRef := "origin/" + branch
	if latestCommit != "" {
		checkRefCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "rev-parse", "--verify", targetRef)
		if err := checkRefCmd.Run(); err != nil {
			targetRef = "FETCH_HEAD"
		}
	}
	behindCmd := exec.Command("git", "-c", "safe.directory=*", "-C", repoDir, "rev-list", "--count", "HEAD.."+targetRef)
	behindOut, _ := behindCmd.Output()
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
			cmd = exec.Command(updateScript, args...)
		} else {
			cmd = exec.Command("sudo", append([]string{updateScript}, args...)...)
		}
		cmd.Dir = repoDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] Update failed: %v\nOutput: %s", err, string(output))
		} else {
			log.Printf("[INFO] Update completed successfully: %s", string(output))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updating",
		"message": "Update initiated. The system will restart momentarily.",
	})
}
