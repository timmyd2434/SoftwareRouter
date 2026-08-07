package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// BackupSnapshot represents a complete system backup (before encryption)
type BackupSnapshot struct {
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Hostname  string            `json:"hostname"`
	Files     map[string]string `json:"files,omitempty"` // file relPath -> raw content
	Config    BackupConfig      `json:"config"`
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

var backupDir = "/var/backups/softrouter"
var softrouterConfigDir = "/etc/softrouter"
var isTesting = false

const backupMagic = "SRBKP01" // Magic header to identify encrypted backup

// deriveKey derives a 32-byte key from the password and salt using PBKDF2-SHA256
func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
}

// encryptBackup encrypts data using AES-256-GCM
func encryptBackup(data []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Format: magic + salt + nonce + ciphertext
	payload := []byte(backupMagic)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return payload, nil
}

// decryptBackup decrypts GCM data with the password
func decryptBackup(data []byte, password string) ([]byte, error) {
	magicLen := len(backupMagic)
	if len(data) < magicLen+16+12 {
		return nil, fmt.Errorf("invalid or corrupted backup file format")
	}

	if string(data[:magicLen]) != backupMagic {
		return nil, fmt.Errorf("not a valid encrypted backup file")
	}

	salt := data[magicLen : magicLen+16]
	nonce := data[magicLen+16 : magicLen+16+12]
	ciphertext := data[magicLen+16+12:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt backup: incorrect password or corrupted file")
	}

	return plaintext, nil
}

// createBackup generates a complete system backup and encrypts it
func createBackup(password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("password is required to create an encrypted backup")
	}

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(backupDir, 0750); err != nil {
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
		Files:     make(map[string]string),
		Config:    BackupConfig{},
	}

	// Walk softrouterConfigDir recursively to capture all configuration files
	_ = filepath.Walk(softrouterConfigDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we cannot access
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(softrouterConfigDir, path)
		if err != nil {
			return nil
		}

		// Skip backup files (e.g. *.bak_...) to keep backup size small and avoid loops
		if strings.Contains(relPath, ".bak") {
			return nil
		}

		// Read file contents
		data, err := os.ReadFile(path)
		if err == nil {
			snapshot.Files[relPath] = string(data)
		}
		return nil
	})

	// System configuration (legacy fallback fields)
	configLock.RLock()
	snapshot.Config.SystemConfig = config
	configLock.RUnlock()

	// Credentials (legacy fallback fields)
	creds := loadCredentials()
	snapshot.Config.Credentials = BackupCredentials{
		Username: creds.Username,
		Password: creds.Password,
	}

	// Interface metadata (legacy fallback fields)
	if metadata, err := loadInterfaceMetadata(); err == nil {
		snapshot.Config.InterfaceMetadata = metadata.Metadata
	}

	// DHCP configuration (legacy fallback fields)
	if dhcpData, err := os.ReadFile(dhcpConfigPath); err == nil {
		var dhcpConfig interface{}
		if err := json.Unmarshal(dhcpData, &dhcpConfig); err == nil {
			snapshot.Config.DHCPConfig = dhcpConfig
		}
	}

	// Firewall rules (legacy fallback fields)
	snapshot.Config.FirewallRules = []string{
		"# Firewall rules snapshot",
		"# Note: Firewall rules should be manually reviewed after restore",
	}

	// Port forwarding rules (legacy fallback fields)
	loadPortForwardingRules()
	pfStoreLock.RLock()
	snapshot.Config.PortForwardingRules = pfStore.Rules
	pfStoreLock.RUnlock()

	// Marshal to JSON
	backupJSON, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup: %w", err)
	}

	// Encrypt the JSON data
	encryptedData, err := encryptBackup(backupJSON, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt backup data: %w", err)
	}

	// Save backup to file with metadata encoded in filename
	// Format: backup-<hostname>-v<version>-<unix_timestamp>.enc
	unixTime := snapshot.Timestamp.Unix()
	backupFilename := fmt.Sprintf("backup-%s-v%s-%d.enc", hostname, snapshot.Version, unixTime)
	backupPath := filepath.Join(backupDir, backupFilename)

	if err := os.WriteFile(backupPath, encryptedData, 0600); err != nil {
		return nil, fmt.Errorf("failed to save encrypted backup file: %w", err)
	}

	return encryptedData, nil
}

// validateBackup decrypts and validates the backup metadata
func validateBackup(data []byte, password string) error {
	decrypted, err := decryptBackup(data, password)
	if err != nil {
		return err
	}

	var snapshot BackupSnapshot
	if err := json.Unmarshal(decrypted, &snapshot); err != nil {
		return fmt.Errorf("invalid decrypted backup format: %w", err)
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

// restoreBackup restores system from an encrypted backup
func restoreBackup(data []byte, password string) error {
	// Validate first (includes decryption test)
	if err := validateBackup(data, password); err != nil {
		return fmt.Errorf("backup validation failed: %w", err)
	}

	decrypted, err := decryptBackup(data, password)
	if err != nil {
		return err
	}

	var snapshot BackupSnapshot
	if err := json.Unmarshal(decrypted, &snapshot); err != nil {
		return err
	}

	// Create encrypted backup of current state before restore using the same password
	if _, err := createBackup(password); err != nil {
		log.Printf("WARNING: Failed to create pre-restore backup: %v", err)
	}

	if len(snapshot.Files) > 0 {
		log.Println("[BACKUP] Restoring configuration files from backup map...")
		// File-based restore
		for relPath, content := range snapshot.Files {
			// SECURITY: Prevent path traversal attacks from crafted backup files
			cleanedRel := filepath.Clean(relPath)
			fullPath := filepath.Join(softrouterConfigDir, cleanedRel)

			// Verify the resolved path is still within softrouterConfigDir
			absConfigDir, _ := filepath.Abs(softrouterConfigDir)
			absFullPath, _ := filepath.Abs(fullPath)
			if !strings.HasPrefix(absFullPath, absConfigDir+string(os.PathSeparator)) && absFullPath != absConfigDir {
				log.Printf("SECURITY: Blocked path traversal in backup restore: %s -> %s", relPath, absFullPath)
				continue
			}

			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
				log.Printf("WARNING: Failed to create directory for %s: %v", fullPath, err)
				continue
			}

			// Write configuration file
			if err := os.WriteFile(fullPath, []byte(content), 0600); err != nil {
				log.Printf("WARNING: Failed to write restored file %s: %v", fullPath, err)
			} else {
				log.Printf("[BACKUP] Restored file: %s", cleanedRel)
			}
		}
	} else {
		log.Println("[BACKUP] Restoring configuration from legacy fallback fields...")
		// Fallback restore from individual fields for old backups
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
			if err := os.WriteFile(dhcpConfigPath, dhcpJSON, 0600); err != nil {
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
	}

	// Reapply restored configuration to the live system immediately
	if !isTesting {
		log.Println("[BACKUP] Re-applying restored configurations to the live system...")

		// 1. Reload main configs
		loadSystemConfig()
		loadTokenSecret()

		// 2. Re-apply custom interfaces (Bonds, VLANs, Bridges, IP configurations)
		applyInterfacesConfig()

		// 3. Re-apply WireGuard
		initWireGuard()

		// 4. Re-apply DHCP configurations
		if store, err := loadDHCPConfig(); err == nil {
			if err := regenerateDnsmasqDHCPConfig(store); err != nil {
				log.Printf("WARNING: Failed to apply restored DHCP configurations: %v", err)
			}
		}

		// 5. Re-apply Port Forwarding and Firewall Manager
		loadPortForwardingRules()
		InitFirewallManager()
		if firewallManager != nil {
			firewallManager.ApplyFirewallRules(true)
		}

		// 6. Re-apply routes, multi-WAN, scheduler, notifications
		initRoutes()
		initWANManager()
		initDynamicRouting()
		initScheduler()
		initNotifications()
	}

	log.Printf("System restored from backup successfully (timestamp: %s)", snapshot.Timestamp.Format(time.RFC3339))
	return nil
}

// listBackups returns available backups by parsing their metadata from filename
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
		if file.IsDir() || filepath.Ext(file.Name()) != ".enc" {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		name := file.Name()
		// Reconstruct metadata from filename
		// Expected format: backup-<hostname>-v<version>-<unix_timestamp>.enc
		nameWithoutExt := strings.TrimSuffix(name, ".enc")
		parts := strings.Split(nameWithoutExt, "-")
		if len(parts) < 4 {
			continue
		}

		// Parse timestamp from last part
		unixStr := parts[len(parts)-1]
		unixTime, err := strconv.ParseInt(unixStr, 10, 64)
		if err != nil {
			continue
		}
		timestamp := time.Unix(unixTime, 0)

		// Parse version from second to last part
		versionWithV := parts[len(parts)-2]
		version := strings.TrimPrefix(versionWithV, "v")

		// Reconstruct hostname from everything in between "backup" and version
		hostname := strings.Join(parts[1:len(parts)-2], "-")

		backups = append(backups, map[string]interface{}{
			"filename":  name,
			"timestamp": timestamp,
			"version":   version,
			"hostname":  hostname,
			"size":      info.Size(),
		})
	}

	return backups, nil
}

// Helper function to create compressed backup (encrypted)
func createCompressedBackup(password string) (string, error) {
	encryptedJSON, err := createBackup(password)
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
		Name: "backup.enc",
		Mode: 0600,
		Size: int64(len(encryptedJSON)),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return "", err
	}

	if _, err := tarWriter.Write(encryptedJSON); err != nil {
		return "", err
	}

	return filepath, nil
}
