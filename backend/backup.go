package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// BackupSnapshot represents a complete system backup
type BackupSnapshot struct {
	Version   string       `json:"version"`
	Timestamp time.Time    `json:"timestamp"`
	Hostname  string       `json:"hostname"`
	Config    BackupConfig `json:"config"`
}

type BackupConfig struct {
	SystemConfig        Config                       `json:"system"`
	Credentials         BackupCredentials            `json:"credentials"`
	InterfaceMetadata   map[string]InterfaceMetadata `json:"interface_metadata"`
	DHCPConfig          interface{}                  `json:"dhcp_config"`
	FirewallRules       []string                     `json:"firewall_rules"`
	PortForwardingRules []PortForwardingRule         `json:"port_forwarding"`
}

type BackupCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"` // Hashed password
}

const backupDir = "/var/backups/softrouter"

// createBackup generates a complete system backup
func createBackup() ([]byte, error) {
	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "router"
	}

	snapshot := BackupSnapshot{
		Version:   "0.12",
		Timestamp: time.Now(),
		Hostname:  hostname,
		Config:    BackupConfig{},
	}

	// System configuration
	configLock.RLock()
	snapshot.Config.SystemConfig = config
	configLock.RUnlock()

	// Credentials
	creds := loadCredentials()
	snapshot.Config.Credentials = BackupCredentials{
		Username: creds.Username,
		Password: creds.Password,
	}

	// Interface metadata
	if metadata, err := loadInterfaceMetadata(); err == nil {
		snapshot.Config.InterfaceMetadata = metadata.Metadata
	}

	// DHCP configuration
	if dhcpData, err := os.ReadFile(dhcpConfigPath); err == nil {
		var dhcpConfig interface{}
		if err := json.Unmarshal(dhcpData, &dhcpConfig); err == nil {
			snapshot.Config.DHCPConfig = dhcpConfig
		}
	}

	// Firewall rules (basic snapshot - just store rule descriptions)
	snapshot.Config.FirewallRules = []string{
		"# Firewall rules snapshot",
		"# Note: Firewall rules should be manually reviewed after restore",
	}

	// Port forwarding rules
	loadPortForwardingRules()
	pfStoreLock.RLock()
	snapshot.Config.PortForwardingRules = pfStore.Rules
	pfStoreLock.RUnlock()

	// Marshal to JSON
	backupJSON, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup: %w", err)
	}

	// Save backup to file with timestamp
	backupFilename := fmt.Sprintf("backup-%s.json", time.Now().Format("2006-01-02-150405"))
	backupPath := filepath.Join(backupDir, backupFilename)

	if err := os.WriteFile(backupPath, backupJSON, 0600); err != nil {
		return nil, fmt.Errorf("failed to save backup file: %w", err)
	}

	return backupJSON, nil
}

// validateBackup checks if a backup is valid and compatible
func validateBackup(data []byte) error {
	var snapshot BackupSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("invalid backup format: %w", err)
	}

	// Check version compatibility
	if snapshot.Version == "" {
		return fmt.Errorf("backup version missing")
	}

	// Basic validation
	if snapshot.Config.Credentials.Username == "" {
		return fmt.Errorf("backup missing credentials")
	}

	return nil
}

// restoreBackup restores system from a backup
func restoreBackup(data []byte) error {
	// Validate first
	if err := validateBackup(data); err != nil {
		return fmt.Errorf("backup validation failed: %w", err)
	}

	var snapshot BackupSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}

	// Create backup of current state before restore
	if _, err := createBackup(); err != nil {
		log.Printf("WARNING: Failed to create pre-restore backup: %v", err)
	}

	// Restore system configuration
	configLock.Lock()
	config = snapshot.Config.SystemConfig
	if err := saveConfigLocked(); err != nil {
		configLock.Unlock()
		return fmt.Errorf("failed to restore config: %w", err)
	}
	configLock.Unlock()

	// Restore credentials
	creds := UserCredentials{
		Username: snapshot.Config.Credentials.Username,
		Password: snapshot.Config.Credentials.Password,
	}
	if err := saveCredentials(creds); err != nil {
		return fmt.Errorf("failed to restore credentials: %w", err)
	}

	// Restore interface metadata
	if len(snapshot.Config.InterfaceMetadata) > 0 {
		metadata := &InterfaceMetadataStore{
			Metadata: snapshot.Config.InterfaceMetadata,
		}
		if err := saveInterfaceMetadata(metadata); err != nil {
			log.Printf("WARNING: Failed to restore interface metadata: %v", err)
		}
	}

	// Restore DHCP configuration
	if snapshot.Config.DHCPConfig != nil {
		dhcpJSON, _ := json.MarshalIndent(snapshot.Config.DHCPConfig, "", "  ")
		if err := os.WriteFile(dhcpConfigPath, dhcpJSON, 0644); err != nil {
			log.Printf("WARNING: Failed to restore DHCP config: %v", err)
		}
	}

	// Restore port forwarding rules
	if len(snapshot.Config.PortForwardingRules) > 0 {
		pfStoreLock.Lock()
		pfStore.Rules = snapshot.Config.PortForwardingRules
		pfStoreLock.Unlock()

		if err := savePortForwardingRules(); err != nil {
			log.Printf("WARNING: Failed to restore port forwarding: %v", err)
		}
	}

	log.Printf("System restored from backup (timestamp: %s)", snapshot.Timestamp.Format(time.RFC3339))

	return nil
}

// listBackups returns available backups
func listBackups() ([]map[string]interface{}, error) {
	files, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]interface{}{}, nil
		}
		return nil, err
	}

	backups := []map[string]interface{}{}
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		// Try to read backup metadata
		backupPath := filepath.Join(backupDir, file.Name())
		data, err := os.ReadFile(backupPath)
		if err != nil {
			continue
		}

		var snapshot BackupSnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			continue
		}

		backups = append(backups, map[string]interface{}{
			"filename":  file.Name(),
			"timestamp": snapshot.Timestamp,
			"version":   snapshot.Version,
			"hostname":  snapshot.Hostname,
			"size":      info.Size(),
		})
	}

	return backups, nil
}

// Helper function to create compressed backup
func createCompressedBackup() (string, error) {
	backupJSON, err := createBackup()
	if err != nil {
		return "", err
	}

	filename := fmt.Sprintf("backup-%s.tar.gz", time.Now().Format("2006-01-02-150405"))
	filepath := filepath.Join(backupDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close() //nolint:errcheck

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close() //nolint:errcheck

	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close() //nolint:errcheck

	// Add backup JSON to tar
	header := &tar.Header{
		Name: "backup.json",
		Mode: 0600,
		Size: int64(len(backupJSON)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return "", err
	}

	if _, err := tarWriter.Write(backupJSON); err != nil {
		return "", err
	}

	return filepath, nil
}
