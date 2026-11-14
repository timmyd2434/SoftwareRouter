package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
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

const (
	backupMagicV1 = "SRBKP01" // legacy: PBKDF2-SHA256, 4096 iterations (read-only support)
	backupMagicV2 = "SRBKP02" // Argon2id with versioned KDF header, header bound as GCM AAD
	backupMagic   = backupMagicV2
)

// Argon2id parameters for new backups (OWASP-recommended class: 64 MiB, t=3, p=4)
const (
	argonTime    uint32 = 3
	argonMemKiB  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonAlgoID  byte   = 1

	// Upper bounds accepted from an (attacker-supplied) backup header, so a
	// crafted file cannot make the router allocate gigabytes during restore.
	argonMaxTime    uint32 = 10
	argonMaxMemKiB  uint32 = 256 * 1024
	argonMaxThreads uint8  = 16

	backupSaltLen = 16
	// magic(7) + algo(1) + time(4) + mem(4) + threads(1) + salt(16)
	backupHeaderLenV2 = 7 + 1 + 4 + 4 + 1 + backupSaltLen
)

// Files that must never be written into a backup archive (secrets that are
// either regenerated per-host or must not travel with an exported file).
var backupExcludedFiles = map[string]bool{
	"token_secret.key":      true,
	"user_credentials.json": true,
}

// deriveKeyLegacy is the old PBKDF2 derivation, kept only to read SRBKP01 files.
func deriveKeyLegacy(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
}

// deriveKeyArgon2id derives a 32-byte key. The password copy is wiped afterwards.
func deriveKeyArgon2id(password string, salt []byte, t, memKiB uint32, threads uint8) []byte {
	pw := []byte(password)
	key := argon2.IDKey(pw, salt, t, memKiB, threads, 32)
	for i := range pw {
		pw[i] = 0
	}
	runtime.KeepAlive(pw)
	return key
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}
	return gcm, nil
}

// encryptBackup encrypts data using AES-256-GCM with an Argon2id-derived key.
// Layout: header(magic|algo|time|mem|threads|salt) | nonce | ciphertext
// The header is authenticated as AAD so KDF parameters cannot be tampered with.
func encryptBackup(data []byte, password string) ([]byte, error) {
	salt := make([]byte, backupSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	header := make([]byte, 0, backupHeaderLenV2)
	header = append(header, []byte(backupMagicV2)...)
	header = append(header, argonAlgoID)
	header = binary.BigEndian.AppendUint32(header, argonTime)
	header = binary.BigEndian.AppendUint32(header, argonMemKiB)
	header = append(header, argonThreads)
	header = append(header, salt...)

	key := deriveKeyArgon2id(password, salt, argonTime, argonMemKiB, argonThreads)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, header)

	payload := append([]byte{}, header...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

// decryptBackup decrypts a backup (SRBKP02 Argon2id, or legacy SRBKP01).
func decryptBackup(data []byte, password string) ([]byte, error) {
	if len(data) < len(backupMagicV1) {
		return nil, fmt.Errorf("invalid or corrupted backup file format")
	}
	switch string(data[:len(backupMagicV1)]) {
	case backupMagicV2:
		return decryptBackupV2(data, password)
	case backupMagicV1:
		return decryptBackupV1(data, password)
	default:
		return nil, fmt.Errorf("not a valid encrypted backup file")
	}
}

func decryptBackupV2(data []byte, password string) ([]byte, error) {
	if len(data) < backupHeaderLenV2+12 {
		return nil, fmt.Errorf("invalid or corrupted backup file format")
	}
	header := data[:backupHeaderLenV2]
	if header[7] != argonAlgoID {
		return nil, fmt.Errorf("unsupported backup KDF")
	}
	t := binary.BigEndian.Uint32(header[8:12])
	mem := binary.BigEndian.Uint32(header[12:16])
	threads := header[16]
	salt := header[17 : 17+backupSaltLen]
	if t < 1 || t > argonMaxTime || mem < 8*1024 || mem > argonMaxMemKiB || threads < 1 || threads > argonMaxThreads {
		return nil, fmt.Errorf("backup KDF parameters out of accepted range")
	}

	key := deriveKeyArgon2id(password, salt, t, mem, threads)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := data[backupHeaderLenV2 : backupHeaderLenV2+gcm.NonceSize()]
	ciphertext := data[backupHeaderLenV2+gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt backup: incorrect password or corrupted file")
	}
	return plaintext, nil
}

func decryptBackupV1(data []byte, password string) ([]byte, error) {
	magicLen := len(backupMagicV1)
	if len(data) < magicLen+16+12 {
		return nil, fmt.Errorf("invalid or corrupted backup file format")
	}
	salt := data[magicLen : magicLen+16]
	nonce := data[magicLen+16 : magicLen+16+12]
	ciphertext := data[magicLen+16+12:]

	key := deriveKeyLegacy(password, salt)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
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

		// SECURITY: never export the session-signing secret or the credential hash
		if backupExcludedFiles[filepath.ToSlash(relPath)] {
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
	// SECURITY: credential hash is no longer exported; Credentials stays empty.

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

			// SECURITY: never let a backup replace the session-signing secret, and
			// only restore credentials onto a host that has none yet (fresh install).
			slashRel := filepath.ToSlash(cleanedRel)
			if slashRel == "token_secret.key" {
				log.Printf("[BACKUP] Skipping %s (host-local secret)", cleanedRel)
				continue
			}
			if slashRel == "user_credentials.json" {
				if _, statErr := os.Stat(fullPath); statErr == nil {
					log.Printf("[BACKUP] Skipping %s (credentials already exist on this host)", cleanedRel)
					continue
				}
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
		if snapshot.Config.Credentials.Username != "" {
			if _, statErr := os.Stat(filepath.Join(softrouterConfigDir, "user_credentials.json")); os.IsNotExist(statErr) {
				creds := UserCredentials{
					Username: snapshot.Config.Credentials.Username,
					Password: snapshot.Config.Credentials.Password,
				}
				if err := saveCredentials(creds); err != nil {
					return fmt.Errorf("failed to restore credentials: %w", err)
				}
			}
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

// deleteBackupFile deletes a specific backup file
func deleteBackupFile(filename string) error {
	matched, _ := regexp.MatchString(`^backup-[\w.-]+\.enc$`, filename)
	if !matched {
		return fmt.Errorf("invalid backup filename format")
	}
	
	safeName := filepath.Base(filename)
	fullPath := filepath.Join(backupDir, safeName)
	
	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup file not found")
		}
		return fmt.Errorf("failed to delete backup: %w", err)
	}
	return nil
}
