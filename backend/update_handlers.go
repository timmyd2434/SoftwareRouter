package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
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

var repoDir = "/home/tim/SoftwareRouter/SoftwareRouter"

func getUpdateStatus(w http.ResponseWriter, r *http.Request) {
	branch := r.URL.Query().Get("branch")
	
	if branch == "" {
		// get current branch
		cmd := exec.Command("git", "-C", repoDir, "branch", "--show-current")
		out, err := cmd.Output()
		if err == nil {
			branch = strings.TrimSpace(string(out))
		} else {
			branch = "main" // fallback
		}
	}

	if branch != "main" && branch != "Dev" {
		respondInvalidRequest(w, "Branch must be 'main' or 'Dev'")
		return
	}

	// Fetch latest
	fetchCmd := exec.Command("git", "-C", repoDir, "fetch", "origin")
	if err := fetchCmd.Run(); err != nil {
		respondSystemError(w, ErrGenericInternalError, "Failed to fetch updates", err)
		return
	}

	// Current branch
	currBranchCmd := exec.Command("git", "-C", repoDir, "branch", "--show-current")
	currBranchOut, _ := currBranchCmd.Output()
	currentBranch := strings.TrimSpace(string(currBranchOut))

	// Current commit
	currCommitCmd := exec.Command("git", "-C", repoDir, "rev-parse", "--short", "HEAD")
	currCommitOut, _ := currCommitCmd.Output()
	currentCommit := strings.TrimSpace(string(currCommitOut))

	// Latest commit
	latestCommitCmd := exec.Command("git", "-C", repoDir, "rev-parse", "--short", "origin/"+branch)
	latestCommitOut, _ := latestCommitCmd.Output()
	latestCommit := strings.TrimSpace(string(latestCommitOut))

	// Behind count
	behindCmd := exec.Command("git", "-C", repoDir, "rev-list", "--count", "HEAD..origin/"+branch)
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

	go func() {
		cmd := exec.Command("sudo", append([]string{"/home/tim/SoftwareRouter/SoftwareRouter/update.sh"}, args...)...)
		cmd.Dir = repoDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] Update failed: %v\nOutput: %s", err, string(output))
		} else {
			log.Printf("[INFO] Update completed successfully")
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updating",
		"message": "Update initiated. The system will restart momentarily.",
	})
}
