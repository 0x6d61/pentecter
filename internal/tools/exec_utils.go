package tools

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// resolveBinary は binary 名を PATH から絶対パスに解決する。
//
// セキュリティ:
//   - パス区切り文字（/ \）を含む名前は拒否（パストラバーサル防止）
//   - exec.LookPath で PATH 内の実在バイナリのみ許可
//   - 絶対パスであることを確認
func resolveBinary(name string) (string, error) {
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("binary name must not contain path separators: %q", name)
	}
	if strings.TrimSpace(name) == "" {
		return "", errors.New("binary name must not be empty")
	}
	absPath, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("binary %q not found in PATH: %w", name, err)
	}
	if !filepath.IsAbs(absPath) {
		return "", fmt.Errorf("resolved path is not absolute: %q", absPath)
	}
	return absPath, nil
}
