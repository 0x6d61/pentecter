package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveRawOutput_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveRawOutput(dir, "10.10.11.100", "nmap -sV 10.10.11.100", "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n")
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("path should not be empty")
	}

	// ファイルが存在するか
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// コマンドがヘッダーに含まれる
	if !strings.Contains(content, "nmap -sV 10.10.11.100") {
		t.Errorf("file should contain command, got:\n%s", content)
	}
	// 出力が含まれる
	if !strings.Contains(content, "22/tcp open  ssh") {
		t.Errorf("file should contain output, got:\n%s", content)
	}
}

func TestSaveRawOutput_CreatesSubdirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := SaveRawOutput(dir, "10.10.11.100", "nmap -sV", "output")
	if err != nil {
		t.Fatal(err)
	}

	// memory/<host>/raw/ ディレクトリが作成されているか
	rawDir := filepath.Join(dir, "10.10.11.100", "raw")
	info, err := os.Stat(rawDir)
	if err != nil {
		t.Fatalf("raw dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("raw path should be a directory")
	}
}

func TestSaveRawOutput_FilenameContainsTool(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveRawOutput(dir, "10.10.11.100", "ffuf -w /usr/share/wordlists -u http://target/FUZZ", "results")
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(path)
	if !strings.Contains(base, "ffuf") {
		t.Errorf("filename should contain tool name, got: %s", base)
	}
	if !strings.HasSuffix(base, ".txt") {
		t.Errorf("filename should end with .txt, got: %s", base)
	}
}

func TestSaveRawOutput_EmptyOutput(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveRawOutput(dir, "10.10.11.100", "echo hello", "")
	if err != nil {
		t.Fatal(err)
	}
	// 空出力でもファイルは作成される（コマンド記録として）
	if path == "" {
		t.Fatal("path should not be empty even with empty output")
	}
}

func TestSaveRawOutput_SpecialCharsInHost(t *testing.T) {
	dir := t.TempDir()
	// ドメイン名をホストとして使用
	path, err := SaveRawOutput(dir, "dev.example.com", "curl http://dev.example.com", "HTTP/1.1 200 OK")
	if err != nil {
		t.Fatal(err)
	}
	// ドメインディレクトリが作成されるか
	if !strings.Contains(path, "dev.example.com") {
		t.Errorf("path should contain host, got: %s", path)
	}
}

func TestExtractToolName(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"nmap -sV -sC 10.10.11.100", "nmap"},
		{"ffuf -w /usr/share/wordlists -u http://target/FUZZ", "ffuf"},
		{"curl -ik http://10.10.11.100/login", "curl"},
		{"searchsploit Apache 2.4.49", "searchsploit"},
		{"python3 exploit.py", "python3"},
		{"./custom-tool --flag", "custom-tool"},
		{"/usr/bin/nmap -sV", "nmap"},
		{"sudo nmap -sV", "nmap"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		got := extractToolName(tt.command)
		if got != tt.want {
			t.Errorf("extractToolName(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}
