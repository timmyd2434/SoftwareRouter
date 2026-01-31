package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
)

// Validation regex for hostnames/IPs to prevent command injection
var hostRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

type PingRequest struct {
	Target string `json:"target"`
	Count  int    `json:"count"`
}

type TracerouteRequest struct {
	Target string `json:"target"`
}

type LogRequest struct {
	Lines int `json:"lines"`
}

type ToolResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// handlePing executes the ping command
func handlePing(w http.ResponseWriter, r *http.Request) {
	var req PingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if !hostRegex.MatchString(req.Target) {
		http.Error(w, "Invalid target format", http.StatusBadRequest)
		return
	}

	if req.Count < 1 || req.Count > 10 {
		req.Count = 4
	}

	// Ping command: ping -c <count> -W 2 <target>
	// -W 2: Wait 2 seconds for response
	cmd := exec.Command("ping", "-c", strconv.Itoa(req.Count), "-W", "2", req.Target)
	output, err := cmd.CombinedOutput()

	resp := ToolResponse{
		Output: string(output),
	}
	if err != nil {
		resp.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTraceroute executes the traceroute command
func handleTraceroute(w http.ResponseWriter, r *http.Request) {
	var req TracerouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if !hostRegex.MatchString(req.Target) {
		http.Error(w, "Invalid target format", http.StatusBadRequest)
		return
	}

	// Traceroute command: traceroute -w 2 -m 15 <target>
	// -w 2: Wait 2 seconds
	// -m 15: Max hops 15 (faster)
	cmd := exec.Command("traceroute", "-w", "2", "-m", "15", req.Target)
	output, err := cmd.CombinedOutput()

	resp := ToolResponse{
		Output: string(output),
	}
	if err != nil {
		resp.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleSystemLogs retrieves journalctl logs for the service
func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	linesStr := r.URL.Query().Get("lines")
	lines := 50
	if l, err := strconv.Atoi(linesStr); err == nil && l > 0 && l <= 500 {
		lines = l
	}

	// journalctl -u softrouter -n <lines> --no-pager
	// If not running as a systemd service, this might return "No entries" or error.
	// Fallback: dmesg or just return a message.
	// For this environment, we might check if we can read /var/log/syslog or similar if not systemd.
	// But let's try journalctl first as it is standard.
	// Also include `-r` for reverse (newest first) ?? No, usually logs are oldest to newest.
	// Let's do standard order.
	cmd := exec.Command("journalctl", "-u", "softrouter", "-n", strconv.Itoa(lines), "--no-pager")
	output, err := cmd.CombinedOutput()

	// If empty, it might be because the service name is wrong or we are running manually.
	// If running manually, maybe show the last few lines of the standard syslog or dmesg?
	// Let's stick to journalctl, assuming production deployment.
	// If output is empty, append a note.
	outStr := string(output)
	if len(outStr) == 0 || err != nil {
		outStr += "\n[No logs found via 'journalctl -u softrouter'. If running manually, check your terminal output.]"
	}

	resp := ToolResponse{
		Output: outStr,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
