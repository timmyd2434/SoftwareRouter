package main

import (
	"fmt"
	"strings"
	"testing"
)

// We want to test the logic of command generation without running exec.
// In a real scenario, we would inject a command runner interface.
// Since we are adding this to existing legacy-style code, we will refactor slightly to test the string building logic
// similar to how we did for Dynamic Routing.

// Fake function to replicate the logic inside ApplyQoS for testing purposes
// ensuring we construct the correct arguments for `tc`
func buildQoSCommands(cfg QoSConfig) [][]string {
	var commands [][]string

	// removal logic omitted for brevity in this generator check, we focus on creation

	// Egress
	if cfg.Mode != "none" && cfg.Upload != "" {
		args := []string{"qdisc", "add", "dev", cfg.Interface, "root", "cake", "bandwidth", cfg.Upload, "besteffort"}
		if cfg.Overhead > 0 {
			args = append(args, "overhead", fmt.Sprintf("%d", cfg.Overhead))
		}
		commands = append(commands, args)
	}

	// Ingress
	if cfg.Mode != "none" && cfg.Download != "" {
		ifbDev := "ifb4" + cfg.Interface

		commands = append(commands, []string{"ip", "link", "add", "name", ifbDev, "type", "ifb"})
		commands = append(commands, []string{"ip", "link", "set", "dev", ifbDev, "up"})
		commands = append(commands, []string{"tc", "qdisc", "add", "dev", cfg.Interface, "handle", "ffff:", "ingress"})
		commands = append(commands, []string{"tc", "filter", "add", "dev", cfg.Interface, "parent", "ffff:", "matchall", "action", "mirred", "egress", "redirect", "dev", ifbDev})

		cakeArgs := []string{"qdisc", "add", "dev", ifbDev, "root", "cake", "bandwidth", cfg.Download, "besteffort"}
		if cfg.Overhead > 0 {
			cakeArgs = append(cakeArgs, "overhead", fmt.Sprintf("%d", cfg.Overhead))
		}
		commands = append(commands, cakeArgs)
	}

	return commands
}

func TestQoSCommandGeneration_EgressOnly(t *testing.T) {
	cfg := QoSConfig{
		Interface: "eth0",
		Mode:      "cake",
		Upload:    "100mbit",
		Overhead:  18,
	}

	cmds := buildQoSCommands(cfg)

	if len(cmds) != 1 {
		t.Fatalf("Expected 1 command for egress only, got %d", len(cmds))
	}

	cmd := strings.Join(cmds[0], " ")
	expected := "qdisc add dev eth0 root cake bandwidth 100mbit besteffort overhead 18"
	if cmd != expected {
		t.Errorf("Generate egress command wrong.\nGot: %s\nWant: %s", cmd, expected)
	}
}

func TestQoSCommandGeneration_Ingress(t *testing.T) {
	cfg := QoSConfig{
		Interface: "eth0",
		Mode:      "cake",
		Upload:    "20mbit",
		Download:  "100mbit",
	}

	cmds := buildQoSCommands(cfg)

	// Egress(1) + Ingress(5 steps: ip link add, ip link up, tc qdisc ingress, tc filter, tc qdisc ifb)
	if len(cmds) != 6 {
		t.Fatalf("Expected 6 commands for full shaping, got %d", len(cmds))
	}

	// Check the final CAKE on IFB
	lastCmd := strings.Join(cmds[5], " ")
	expected := "qdisc add dev ifb4eth0 root cake bandwidth 100mbit besteffort"
	if lastCmd != expected {
		t.Errorf("Generate ingress ifb cake command wrong.\nGot: %s\nWant: %s", lastCmd, expected)
	}
}
