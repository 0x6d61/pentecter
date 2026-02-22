package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const attackTreeFileName = "attack_tree.json"
const attackTreeBackupDir = "attack_tree_backup"

// BackupManager は AttackDataTree のバックアップを管理する。
type BackupManager struct {
	baseDir string
	host    string
	tree    *AttackDataTree
}

// NewBackupManager は BackupManager を作成する。
func NewBackupManager(baseDir, host string, tree *AttackDataTree) *BackupManager {
	return &BackupManager{
		baseDir: baseDir,
		host:    host,
		tree:    tree,
	}
}

// Save は AttackDataTree の最新状態を attack_tree.json に保存する。
// tmpfile + rename で atomic write を行う。
func (b *BackupManager) Save() error {
	snap := b.tree.Snapshot()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	dir := filepath.Join(b.baseDir, b.host)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	targetPath := filepath.Join(dir, attackTreeFileName)

	// Atomic write: write to temp file, then rename
	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// Cleanup tmp on rename failure (best-effort)
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// SaveBackup は attack_tree_backup/<timestamp>.json にバックアップをコピーする。
func (b *BackupManager) SaveBackup() error {
	snap := b.tree.Snapshot()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	backupDir := filepath.Join(b.baseDir, b.host, attackTreeBackupDir)
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s.json", timestamp)
	filePath := filepath.Join(backupDir, filename)

	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	return nil
}

// LoadAttackDataTree は attack_tree.json から AttackDataTree を復元する。
// ファイルが存在しない場合は nil, nil を返す。
func LoadAttackDataTree(baseDir, host string) (*AttackDataTree, error) {
	filePath := filepath.Join(baseDir, host, attackTreeFileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read attack tree: %w", err)
	}

	var snap AttackDataSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal attack tree: %w", err)
	}

	return RestoreAttackDataTree(snap), nil
}
