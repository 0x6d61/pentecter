package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

func newTestRunner(defs ...*tools.ToolDef) *tools.CommandRunner {
	reg := tools.NewRegistry()
	for _, d := range defs {
		reg.Register(d)
	}
	bl := tools.NewBlacklist([]string{`rm\s+-rf\s+/`, `dd\s+if=`})
	store := tools.NewLogStore()
	return tools.NewCommandRunner(reg, bl, store)
}

func TestCommandRunner_Run_DirectExec(t *testing.T) {
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal, // 明示的に自動承認
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 5,
			TailLines: 5,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo hello-runner")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal for docker/explicit false tool")
	}

	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("execution error: %v", res.Err)
	}
	if !containsSubstring(output, "hello-runner") {
		t.Errorf("expected 'hello-runner' in output, got: %v", output)
	}
}

func TestCommandRunner_Run_BlacklistedCommand(t *testing.T) {
	runner := newTestRunner()

	ctx := context.Background()
	_, _, _, err := runner.Run(ctx, "rm -rf /")
	if err == nil {
		t.Error("expected error for blacklisted command, got nil")
	}
	if !strings.Contains(err.Error(), "blacklist") {
		t.Errorf("expected blacklist error, got: %v", err)
	}
}

func TestCommandRunner_Run_RequiresProposal_NoDocker(t *testing.T) {
	// Docker なし + proposal_required 未設定 → 要承認
	runner := newTestRunner(&tools.ToolDef{
		Name: "msfconsole",
		// ProposalRequired: nil → Docker なし → true がデフォルト
	})

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "msfconsole -r exploit.rc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !needsProposal {
		t.Error("expected needsProposal=true for host-direct tool")
	}
}

func TestCommandRunner_Run_UnknownBinary_HostExecRequiresProposal(t *testing.T) {
	// ToolDef が見つからない場合はホスト実行として要承認扱い
	runner := newTestRunner() // empty registry

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "someunknowntool --flag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !needsProposal {
		t.Error("expected needsProposal=true for unknown tool")
	}
}

func TestCommandRunner_NeedsProposal(t *testing.T) {
	falseVal := false
	trueVal := true

	cases := []struct {
		name string
		def  *tools.ToolDef
		want bool
	}{
		{
			name: "Docker あり → 自動承認",
			def:  &tools.ToolDef{Name: "nmap", Docker: &tools.DockerConfig{Image: "instrumentisto/nmap", Fallback: true}},
			want: false,
		},
		{
			name: "Docker なし → 要承認",
			def:  &tools.ToolDef{Name: "msfconsole"},
			want: true,
		},
		{
			name: "proposal_required: false → 強制自動承認",
			def:  &tools.ToolDef{Name: "curl", ProposalRequired: &falseVal},
			want: false,
		},
		{
			name: "proposal_required: true → 強制要承認",
			def:  &tools.ToolDef{Name: "nmap", Docker: &tools.DockerConfig{Image: "instrumentisto/nmap"}, ProposalRequired: &trueVal},
			want: true,
		},
	}

	for _, c := range cases {
		got := c.def.IsProposalRequired()
		if got != c.want {
			t.Errorf("%s: IsProposalRequired() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCommandRunner_ParseCommand(t *testing.T) {
	cases := []struct {
		input  string
		binary string
		args   []string
	}{
		{"nmap -sV 10.0.0.5", "nmap", []string{"-sV", "10.0.0.5"}},
		{"nikto -h http://10.0.0.5/", "nikto", []string{"-h", "http://10.0.0.5/"}},
		{"echo hello world", "echo", []string{"hello", "world"}},
	}

	for _, c := range cases {
		binary, args := tools.ParseCommand(c.input)
		if binary != c.binary {
			t.Errorf("ParseCommand(%q) binary: got %q, want %q", c.input, binary, c.binary)
		}
		if len(args) != len(c.args) {
			t.Errorf("ParseCommand(%q) args len: got %d, want %d", c.input, len(args), len(c.args))
			continue
		}
		for i, a := range c.args {
			if args[i] != a {
				t.Errorf("ParseCommand(%q) args[%d]: got %q, want %q", c.input, i, args[i], a)
			}
		}
	}
}

func containsSubstring(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
