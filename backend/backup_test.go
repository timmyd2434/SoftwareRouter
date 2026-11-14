package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupAndRestore(t *testing.T) {
	// 1. Create temporary directories
	tempConfigDir, err := os.MkdirTemp("", "softrouter-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp config dir: %v", err)
	}
	defer os.RemoveAll(tempConfigDir)

	tempBackupDir, err := os.MkdirTemp("", "softrouter-backup-test")
	if err != nil {
		t.Fatalf("Failed to create temp backup dir: %v", err)
	}
	defer os.RemoveAll(tempBackupDir)

	// Override package-level variables
	oldConfigDir := softrouterConfigDir
	oldBackupDir := backupDir
	oldIsTesting := isTesting
	softrouterConfigDir = tempConfigDir
	backupDir = tempBackupDir
	isTesting = true
	defer func() {
		softrouterConfigDir = oldConfigDir
		backupDir = oldBackupDir
		isTesting = oldIsTesting
	}()

	// 2. Create mock configuration files
	filesToCreate := map[string]string{
		"config.json":                   `{"adguard":{"url":"http://localhost:3000"}}`,
		"interfaces_config.json":        `{"vlans":{"eth1.10":{"parentInterface":"eth1","vlanId":10}}}`,
		"user_credentials.json":         `{"username":"testadmin","password":"hashedpassword"}`,
		"token_secret.key":              `super-secret-signing-key`,
		"vpn_clients/client1.conf":      `client-config-data`,
		"nested/dir/deep/file.txt":      `nested-content`,
		"should_skip.bak":               `should-be-ignored`,
	}

	for relPath, content := range filesToCreate {
		fullPath := filepath.Join(tempConfigDir, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
			t.Fatalf("Failed to create dir for %s: %v", relPath, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to write mock file %s: %v", relPath, err)
		}
	}
	// 3. Trigger backup
	backupData, err := createBackup("testpassword123")
	if err != nil {
		t.Fatalf("createBackup failed: %v", err)
	}

	// 4. Validate backup contents
	decryptedBytes, err := decryptBackup(backupData, "testpassword123")
	if err != nil {
		t.Fatalf("decryptBackup failed: %v", err)
	}

	var snapshot BackupSnapshot
	if err := json.Unmarshal(decryptedBytes, &snapshot); err != nil {
		t.Fatalf("Failed to unmarshal backup JSON: %v", err)
	}

	if snapshot.Version != "0.12" {
		t.Errorf("Expected version 0.12, got %s", snapshot.Version)
	}

	if snapshot.Files == nil {
		t.Fatal("Files map is nil in BackupSnapshot")
	}

	// Verify files that should be present
	expectedPresent := []string{
		"config.json",
		"interfaces_config.json",
		"vpn_clients/client1.conf",
		"nested/dir/deep/file.txt",
	}
	for _, relPath := range expectedPresent {
		content, ok := snapshot.Files[relPath]
		if !ok {
			t.Errorf("Expected file %s to be present in backup map", relPath)
		}
		if content != filesToCreate[relPath] {
			t.Errorf("Content mismatch for %s. Expected '%s', got '%s'", relPath, filesToCreate[relPath], content)
		}
	}

	// Secrets must never be exported
	for _, secret := range []string{"token_secret.key", "user_credentials.json"} {
		if _, ok := snapshot.Files[secret]; ok {
			t.Errorf("%s must be excluded from backups", secret)
		}
	}
	if snapshot.Config.Credentials.Password != "" {
		t.Error("credential hash must not be exported in legacy fields")
	}

	// Verify skipped files
	if _, ok := snapshot.Files["should_skip.bak"]; ok {
		t.Error("File should_skip.bak should have been skipped in backup")
	}

	// 5. Clean/delete files from the config directory to simulate loss
	for relPath := range filesToCreate {
		fullPath := filepath.Join(tempConfigDir, relPath)
		_ = os.Remove(fullPath)
	}

	// 6. Restore from backup
	// Temporarily bypass real service reload routines since they require running commands/systems
	// We just want to test file restoration logic
	err = restoreBackup(backupData, "testpassword123")
	if err != nil {
		t.Fatalf("restoreBackup failed: %v", err)
	}
	// 7. Verify all files are restored with exact contents
	for relPath, expectedContent := range filesToCreate {
		if relPath == "should_skip.bak" || relPath == "token_secret.key" || relPath == "user_credentials.json" {
			// This was not backed up, so it should not be restored
			fullPath := filepath.Join(tempConfigDir, relPath)
			if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
				t.Errorf("should_skip.bak should not exist after restore")
			}
			continue
		}

		fullPath := filepath.Join(tempConfigDir, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("Failed to read restored file %s: %v", relPath, err)
			continue
		}

		if string(data) != expectedContent {
			t.Errorf("Restored content mismatch for %s. Expected '%s', got '%s'", relPath, expectedContent, string(data))
		}
	}
}

func TestBackupFormatV2Argon2id(t *testing.T) {
	enc, err := encryptBackup([]byte("hello world"), "pw-123456")
	if err != nil {
		t.Fatal(err)
	}
	if string(enc[:7]) != backupMagicV2 {
		t.Fatalf("expected %s header", backupMagicV2)
	}
	if out, err := decryptBackup(enc, "pw-123456"); err != nil || string(out) != "hello world" {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := decryptBackup(enc, "wrong"); err == nil {
		t.Error("wrong password must fail")
	}
	// Tampering with KDF header must be detected (AAD) or rejected
	tampered := append([]byte{}, enc...)
	tampered[8+3]++ // change time cost
	if _, err := decryptBackup(tampered, "pw-123456"); err == nil {
		t.Error("tampered header must fail")
	}
	// Absurd KDF params from a crafted file are rejected before allocation
	crafted := append([]byte{}, enc...)
	crafted[12], crafted[13], crafted[14], crafted[15] = 0xff, 0xff, 0xff, 0xff
	if _, err := decryptBackup(crafted, "pw-123456"); err == nil {
		t.Error("oversized memory param must be rejected")
	}
}

func TestBackupLegacyV1StillReadable(t *testing.T) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	key := deriveKeyLegacy("legacy-pw", salt)
	gcm, _ := newGCM(key)
	ct := gcm.Seal(nil, nonce, []byte("old data"), nil)
	blob := append([]byte(backupMagicV1), salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	if out, err := decryptBackup(blob, "legacy-pw"); err != nil || string(out) != "old data" {
		t.Fatalf("legacy backup unreadable: %v", err)
	}
}
