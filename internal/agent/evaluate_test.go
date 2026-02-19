package agent

import (
	"testing"
	"time"
)

func TestIsFailedOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		// 既存パターン
		{"empty output", "", true},
		{"host down", "Nmap done: 1 IP address (0 hosts up) scanned in 1.85 seconds", true},
		{"host seems down", "Note: Host seems down.", true},
		{"connection refused", "curl: (7) Failed to connect: Connection refused", true},
		{"no route", "No route to host", true},
		{"network unreachable", "connect: Network is unreachable", true},
		{"name resolution", "Name or service not known", true},
		{"error prefix", "Error: exec failed", true},
		{"successful nmap", "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http", false},
		{"successful curl", "HTTP/1.1 200 OK\nContent-Type: text/html", false},
		{"partial output", "Starting Nmap 7.95\nSome results here", false},
		// 新パターン: プログラムエラー
		{"SyntaxError", "  File \"<string>\", line 1\nSyntaxError: invalid syntax", true},
		{"command not found", "bash: nmap: command not found", true},
		{"No such file or directory", "cat: /etc/secret: No such file or directory", true},
		{"Permission denied", "bash: /usr/sbin/nmap: Permission denied", true},
		{"Traceback", "Traceback (most recent call last):\n  File ...", true},
		{"ModuleNotFoundError", "ModuleNotFoundError: No module named 'requests'", true},
		{"ImportError", "ImportError: cannot import name 'foo'", true},
		{"Go panic", "panic: runtime error: index out of range", true},
		{"NameError python", "NameError: name 'x' is not defined", true},
		{"segfault", "Segmentation fault (core dumped)", true},
		// 偽陽性の確認
		{"normal nmap output", "PORT   STATE SERVICE\n80/tcp open  http\n443/tcp open  https", false},
		{"normal ls output", "bin  etc  home  lib  usr  var", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFailedOutput(tt.output)
			if got != tt.want {
				t.Errorf("isFailedOutput(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestContainsCI(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"Hello World", "hello", true},
		{"Connection Refused", "connection refused", true},
		{"foo", "bar", false},
		{"", "", true},
		{"short", "longer string", false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.sub, func(t *testing.T) {
			got := containsCI(tt.s, tt.sub)
			if got != tt.want {
				t.Errorf("containsCI(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
			}
		})
	}
}

func TestExtractBinary(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"simple command", "nmap -sV 10.0.0.5", "nmap"},
		{"absolute path", "/usr/bin/nmap -sV 10.0.0.5", "nmap"},
		{"relative path", "./exploit.sh", "exploit.sh"},
		{"empty string", "", ""},
		{"command only", "whoami", "whoami"},
		{"python3 script", "python3 -c \"print('hello')\"", "python3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractBinary(tt.command); got != tt.want {
				t.Errorf("extractBinary(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestIsCommandRepetition(t *testing.T) {
	tests := []struct {
		name    string
		history []commandEntry
		want    bool
	}{
		{
			name: "3 of same binary in last 5",
			history: []commandEntry{
				{Command: "nmap -sV 10.0.0.5"},
				{Command: "nmap -sS 10.0.0.5"},
				{Command: "nmap -A 10.0.0.5"},
			},
			want: true,
		},
		{
			name: "below threshold",
			history: []commandEntry{
				{Command: "nmap -sV 10.0.0.5"},
				{Command: "nmap -sS 10.0.0.5"},
			},
			want: false,
		},
		{
			name: "mixed binaries no repetition",
			history: []commandEntry{
				{Command: "nmap -sV 10.0.0.5"},
				{Command: "curl http://10.0.0.5"},
				{Command: "nmap -sS 10.0.0.5"},
				{Command: "python3 exploit.py"},
				{Command: "curl http://10.0.0.5/api"},
			},
			want: false,
		},
		{
			name: "python3 repeated 3 times in 5",
			history: []commandEntry{
				{Command: "python3 -c \"import os\""},
				{Command: "curl http://target"},
				{Command: "python3 -c \"print('a')\""},
				{Command: "python3 exploit.py"},
			},
			want: true,
		},
		{
			name:    "empty history",
			history: nil,
			want:    false,
		},
		{
			name: "only last 5 checked - curl 3 times",
			history: []commandEntry{
				{Command: "nmap -sV 10.0.0.1"},
				{Command: "nmap -sS 10.0.0.1"},
				{Command: "nmap -A 10.0.0.1"},
				// 直近5件
				{Command: "curl http://target"},
				{Command: "python3 exploit.py"},
				{Command: "curl http://target/api"},
				{Command: "whoami"},
				{Command: "curl http://target/v2"},
			},
			want: true, // curl が直近5件中3回
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Loop{history: tt.history}
			if got := l.isCommandRepetition(); got != tt.want {
				t.Errorf("isCommandRepetition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildCommandSummary(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		output   string
		wantSub  string // 結果に含まれるべき部分文字列
	}{
		{
			name:     "success exit 0",
			exitCode: 0,
			output:   "line1\nline2\nline3",
			wantSub:  "exit 0",
		},
		{
			name:     "failure exit 1",
			exitCode: 1,
			output:   "SyntaxError: invalid syntax",
			wantSub:  "exit 1",
		},
		{
			name:     "failure exit 2 with error",
			exitCode: 2,
			output:   "bash: nmap: command not found",
			wantSub:  "command not found",
		},
		{
			name:     "success with many lines",
			exitCode: 0,
			output:   "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12",
			wantSub:  "12 lines",
		},
		{
			name:     "empty output",
			exitCode: 0,
			output:   "",
			wantSub:  "exit 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCommandSummary(tt.exitCode, tt.output)
			if got == "" {
				t.Error("buildCommandSummary returned empty string")
			}
			if !containsCI(got, tt.wantSub) {
				t.Errorf("buildCommandSummary(%d, %q) = %q, want substring %q",
					tt.exitCode, tt.output, got, tt.wantSub)
			}
		})
	}
}

func TestEvaluateResult_ExitCodeNonZero(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   1,
		lastToolOutput: "some output",
		events:         evCh,
	}
	l.evaluateResult()
	if l.consecutiveFailures != 1 {
		t.Errorf("consecutiveFailures = %d, want 1 (exit code != 0 should count as failure)", l.consecutiveFailures)
	}
}

func TestEvaluateResult_ExitCodeZero_SuccessfulOutput(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   0,
		lastToolOutput: "PORT 80/tcp open http",
		events:         evCh,
	}
	l.evaluateResult()
	if l.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures = %d, want 0 (exit 0 + good output = success)", l.consecutiveFailures)
	}
}

func TestBuildHistory_WithSummary(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target: NewTarget(1, "10.0.0.1"),
		events: evCh,
		history: []commandEntry{
			{Command: "nmap -sV 10.0.0.5", ExitCode: 0, Summary: "PORT 22/tcp open ssh"},
			{Command: "curl http://10.0.0.5", ExitCode: 0, Summary: "HTTP/1.1 200 OK"},
			{Command: "nikto -h 10.0.0.5", ExitCode: 1, Summary: ""},
		},
	}
	got := l.buildHistory()

	// エントリ1: summary あり → "exit 0: PORT 22/tcp open ssh"
	if !containsCI(got, "exit 0: PORT 22/tcp open ssh") {
		t.Errorf("expected summary in history entry 1, got:\n%s", got)
	}
	// エントリ2: summary あり → "exit 0: HTTP/1.1 200 OK"
	if !containsCI(got, "exit 0: HTTP/1.1 200 OK") {
		t.Errorf("expected summary in history entry 2, got:\n%s", got)
	}
	// エントリ3: summary なし → "exit 1" のみ（コロンなし）
	if containsCI(got, "exit 1:") {
		t.Errorf("entry 3 has empty summary, should not have colon after exit code, got:\n%s", got)
	}
	if !containsCI(got, "exit 1") {
		t.Errorf("expected exit code 1 in history entry 3, got:\n%s", got)
	}
}

func TestBuildHistory_EmptySummary_NoColon(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target: NewTarget(1, "10.0.0.1"),
		events: evCh,
		history: []commandEntry{
			{Command: "whoami", ExitCode: 0, Summary: ""},
		},
	}
	got := l.buildHistory()

	// summary が空なら "exit 0" のみで、コロンは付かない
	if containsCI(got, "exit 0:") {
		t.Errorf("empty summary should not produce colon, got:\n%s", got)
	}
}

func TestEvaluateResult_Repetition_CountsAsFailure(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   0,
		lastToolOutput: "normal output",
		events:         evCh,
		history: []commandEntry{
			{Command: "python3 a.py", Time: time.Now()},
			{Command: "python3 b.py", Time: time.Now()},
			{Command: "python3 c.py", Time: time.Now()},
		},
	}
	l.evaluateResult()
	if l.consecutiveFailures != 1 {
		t.Errorf("consecutiveFailures = %d, want 1 (repetition should count as failure)", l.consecutiveFailures)
	}
}
