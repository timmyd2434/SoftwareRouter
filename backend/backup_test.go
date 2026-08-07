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
		"user_credentials.json",
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
		if relPath == "should_skip.bak" {
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
