package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSaveRawOutput_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveRawOutput(dir, "10.10.11.100", "nmap -sV 10.10.11.100", "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n", 0)
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

	// JSON としてパースできるか
	var entry RawOutputEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("file should be valid JSON: %v", err)
	}

	// コマンドが含まれる
	if entry.Command != "nmap -sV 10.10.11.100" {
		t.Errorf("command mismatch: got %q", entry.Command)
	}
	// 出力が含まれる
	if !strings.Contains(entry.Output, "22/tcp open  ssh") {
		t.Errorf("output should contain scan results, got: %q", entry.Output)
	}
}

func TestSaveRawOutput_CreatesSubdirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := SaveRawOutput(dir, "10.10.11.100", "nmap -sV", "output", 0)
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
	path, err := SaveRawOutput(dir, "10.10.11.100", "ffuf -w /usr/share/wordlists -u http://target/FUZZ", "results", 0)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(path)
	if !strings.Contains(base, "ffuf") {
		t.Errorf("filename should contain tool name, got: %s", base)
	}
	if !strings.HasSuffix(base, ".json") {
		t.Errorf("filename should end with .json, got: %s", base)
	}
}

func TestSaveRawOutput_EmptyOutput(t *testing.T) {
	dir := t.TempDir()
	path, err := SaveRawOutput(dir, "10.10.11.100", "echo hello", "", 0)
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
	path, err := SaveRawOutput(dir, "dev.example.com", "curl http://dev.example.com", "HTTP/1.1 200 OK", 0)
	if err != nil {
		t.Fatal(err)
	}
	// ドメインディレクトリが作成されるか
	if !strings.Contains(path, "dev.example.com") {
		t.Errorf("path should contain host, got: %s", path)
	}
}

func TestSaveRawOutput_JSONStructure(t *testing.T) {
	dir := t.TempDir()
	command := "nmap -sV -p- 10.10.11.100"
	output := "PORT   STATE SERVICE\n22/tcp open  ssh"
	exitCode := 1

	path, err := SaveRawOutput(dir, "10.10.11.100", command, output, exitCode)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var entry RawOutputEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("should be valid JSON: %v", err)
	}

	// ID が空でない
	if entry.ID == "" {
		t.Error("ID should not be empty")
	}

	// Command が一致
	if entry.Command != command {
		t.Errorf("Command = %q, want %q", entry.Command, command)
	}

	// Output が一致
	if entry.Output != output {
		t.Errorf("Output = %q, want %q", entry.Output, output)
	}

	// ExitCode が一致
	if entry.ExitCode != exitCode {
		t.Errorf("ExitCode = %d, want %d", entry.ExitCode, exitCode)
	}

	// Timestamp が RFC3339 形式
	if _, err := time.Parse(time.RFC3339, entry.Timestamp); err != nil {
		t.Errorf("Timestamp %q is not valid RFC3339: %v", entry.Timestamp, err)
	}

	// Tool が extractToolName の結果と一致
	expectedTool := extractToolName(command)
	if entry.Tool != expectedTool {
		t.Errorf("Tool = %q, want %q", entry.Tool, expectedTool)
	}
}

func TestSaveRawOutput_FilePermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission check not reliable on Windows")
	}

	dir := t.TempDir()
	path, err := SaveRawOutput(dir, "10.10.11.100", "nmap -sV", "output", 0)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permission = %o, want 0600", perm)
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
