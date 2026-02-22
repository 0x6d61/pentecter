package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupManager_Save(t *testing.T) {
	dir := t.TempDir()
	tree := NewAttackDataTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	mgr := NewBackupManager(dir, "10.10.11.100", tree)
	if err := mgr.Save(); err != nil {
		t.Fatal(err)
	}

	// ファイルが作成されているか
	filePath := filepath.Join(dir, "10.10.11.100", attackTreeFileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}

	// JSON として有効か
	var snap AttackDataSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if snap.Host != "10.10.11.100" {
		t.Errorf("Host = %q, want 10.10.11.100", snap.Host)
	}
	if len(snap.Ports) != 2 {
		t.Errorf("Ports = %d, want 2", len(snap.Ports))
	}
}

func TestBackupManager_Save_Overwrite(t *testing.T) {
	dir := t.TempDir()
	tree := NewAttackDataTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	mgr := NewBackupManager(dir, "10.10.11.100", tree)
	if err := mgr.Save(); err != nil {
		t.Fatal(err)
	}

	// Add more data and save again
	tree.AddPort(443, "https", "nginx")
	if err := mgr.Save(); err != nil {
		t.Fatal(err)
	}

	// Load and verify updated data
	filePath := filepath.Join(dir, "10.10.11.100", attackTreeFileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var snap AttackDataSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Ports) != 2 {
		t.Errorf("Ports = %d, want 2 after overwrite", len(snap.Ports))
	}
}

func TestBackupManager_SaveBackup(t *testing.T) {
	dir := t.TempDir()
	tree := NewAttackDataTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	mgr := NewBackupManager(dir, "10.10.11.100", tree)
	if err := mgr.SaveBackup(); err != nil {
		t.Fatal(err)
	}

	// バックアップディレクトリにファイルが作成されているか
	backupDir := filepath.Join(dir, "10.10.11.100", attackTreeBackupDir)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 backup file, got %d", len(entries))
	}

	// ファイル名が .json で終わるか
	name := entries[0].Name()
	if filepath.Ext(name) != ".json" {
		t.Errorf("backup file should be .json, got: %s", name)
	}
}

func TestLoadAttackDataTree(t *testing.T) {
	dir := t.TempDir()
	tree := NewAttackDataTree("10.10.11.100", 3)
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)

	// Save
	mgr := NewBackupManager(dir, "10.10.11.100", tree)
	if err := mgr.Save(); err != nil {
		t.Fatal(err)
	}

	// Load
	loaded, err := LoadAttackDataTree(dir, "10.10.11.100")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("loaded should not be nil")
	}

	// Verify
	if loaded.Host != "10.10.11.100" {
		t.Errorf("Host = %q", loaded.Host)
	}
	if loaded.MaxParallel != 3 {
		t.Errorf("MaxParallel = %d, want 3", loaded.MaxParallel)
	}
	if len(loaded.Ports) != 2 {
		t.Fatalf("Ports = %d, want 2", len(loaded.Ports))
	}
	// Port 80 EndpointEnum should be Complete
	if loaded.Ports[0].EndpointEnum != StatusComplete {
		t.Errorf("EndpointEnum = %d, want Complete", loaded.Ports[0].EndpointEnum)
	}
	// Children preserved
	if len(loaded.Ports[0].Children) != 1 {
		t.Fatalf("children = %d, want 1", len(loaded.Ports[0].Children))
	}
}

func TestLoadAttackDataTree_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	loaded, err := LoadAttackDataTree(dir, "nonexistent")
	if err != nil {
		t.Fatalf("should not error on missing file, got: %v", err)
	}
	if loaded != nil {
		t.Error("should return nil for missing file")
	}
}
