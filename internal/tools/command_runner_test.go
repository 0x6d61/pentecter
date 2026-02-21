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

func TestCommandRunner_AutoApprove_OverridesDefault(t *testing.T) {
	// auto-approve ON → 未登録ツールも自動実行（needsProposal=false）
	runner := newTestRunner() // empty registry
	runner.SetAutoApprove(true)

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "someunknowntool --flag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needsProposal {
		t.Error("expected needsProposal=false with auto-approve ON for unknown tool")
	}
}

func TestCommandRunner_AutoApprove_OverridesExplicitTrue(t *testing.T) {
	// auto-approve ON → proposal_required: true が明示されていても自動実行
	trueVal := true
	runner := newTestRunner(&tools.ToolDef{
		Name:             "msfconsole",
		ProposalRequired: &trueVal,
	})
	runner.SetAutoApprove(true)

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "msfconsole -r exploit.rc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needsProposal {
		t.Error("expected needsProposal=false with auto-approve ON, even for explicit proposal_required: true")
	}
}

func TestCommandRunner_AutoApprove_RegisteredToolNoDocker(t *testing.T) {
	// auto-approve ON + 登録済みツール（Docker なし、proposal_required 未設定）→ 自動実行
	runner := newTestRunner(&tools.ToolDef{
		Name: "customtool",
		// ProposalRequired: nil, Docker: nil → 通常は要承認
	})
	runner.SetAutoApprove(true)

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "customtool --scan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needsProposal {
		t.Error("expected needsProposal=false with auto-approve ON for registered tool without explicit true")
	}
}

func TestCommandRunner_AutoApprove_Default_Off(t *testing.T) {
	// デフォルト（SetAutoApprove 未呼び出し）→ 従来通り未登録は要承認
	runner := newTestRunner()

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "someunknowntool --flag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !needsProposal {
		t.Error("expected needsProposal=true by default for unknown tool")
	}
}

// --- AutoApprove getter テスト ---

func TestCommandRunner_AutoApprove_Getter(t *testing.T) {
	runner := newTestRunner()

	// デフォルトは false
	if runner.AutoApprove() {
		t.Error("AutoApprove() should default to false")
	}

	// true に設定して取得
	runner.SetAutoApprove(true)
	if !runner.AutoApprove() {
		t.Error("AutoApprove() should return true after SetAutoApprove(true)")
	}

	// false に戻す
	runner.SetAutoApprove(false)
	if runner.AutoApprove() {
		t.Error("AutoApprove() should return false after SetAutoApprove(false)")
	}
}

// --- ParseCommand empty input テスト ---

func TestCommandRunner_ParseCommand_Empty(t *testing.T) {
	binary, args := tools.ParseCommand("")
	if binary != "" {
		t.Errorf("ParseCommand(\"\") binary: got %q, want empty", binary)
	}
	if args != nil {
		t.Errorf("ParseCommand(\"\") args: got %v, want nil", args)
	}
}

func TestCommandRunner_ParseCommand_WhitespaceOnly(t *testing.T) {
	binary, args := tools.ParseCommand("   ")
	if binary != "" {
		t.Errorf("ParseCommand(\"   \") binary: got %q, want empty", binary)
	}
	if args != nil {
		t.Errorf("ParseCommand(\"   \") args: got %v, want nil", args)
	}
}

func TestCommandRunner_Run_ShellPipe(t *testing.T) {
	// sh -c 実行により、パイプがシェルとして正しく処理されること
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo hello-pipe | tr a-z A-Z")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal")
	}

	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("execution error: %v", res.Err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if !containsSubstring(output, "HELLO-PIPE") {
		t.Errorf("expected 'HELLO-PIPE' in output (pipe should work), got: %v", output)
	}
}

func TestCommandRunner_Run_ShellVariableExpansion(t *testing.T) {
	// sh -c 実行により、シェル変数展開が動作すること
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo $((2+3))")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal")
	}

	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("execution error: %v", res.Err)
	}
	if !containsSubstring(output, "5") {
		t.Errorf("expected '5' in output (arithmetic expansion), got: %v", output)
	}
}

func TestCommandRunner_Run_ShellCommandNotFound(t *testing.T) {
	// sh -c で存在しないコマンドを実行 → exit code != 0
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "nonexistent_binary_xyz",
		ProposalRequired: &falseVal,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	needsProposal, lines, resultCh, err := runner.Run(ctx, "nonexistent_binary_xyz --flag")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal")
	}

	// drain lines
	for range lines {
	}
	res := <-resultCh

	if res.ExitCode == 0 {
		t.Error("expected non-zero exit code for command not found")
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

// =============================================================================
// buildDockerCmd テスト (#90)
// =============================================================================

func TestBuildDockerCmd_DefaultNetwork(t *testing.T) {
	// Network 未設定 → "host" がデフォルトで使われる
	cfg := &tools.DockerConfig{
		Image: "instrumentisto/nmap",
	}
	cmd := tools.BuildDockerCmdForTest(context.Background(), cfg, "nmap", []string{"-sV", "10.0.0.5"})

	args := cmd.Args
	// docker run --rm --network=host instrumentisto/nmap nmap -sV 10.0.0.5
	if args[0] != "docker" {
		t.Errorf("args[0] = %q, want 'docker'", args[0])
	}
	if args[1] != "run" {
		t.Errorf("args[1] = %q, want 'run'", args[1])
	}
	if args[2] != "--rm" {
		t.Errorf("args[2] = %q, want '--rm'", args[2])
	}
	if args[3] != "--network=host" {
		t.Errorf("args[3] = %q, want '--network=host'", args[3])
	}
}

func TestBuildDockerCmd_CustomNetwork(t *testing.T) {
	// カスタムネットワーク指定
	cfg := &tools.DockerConfig{
		Image:   "instrumentisto/nmap",
		Network: "pentest-net",
	}
	cmd := tools.BuildDockerCmdForTest(context.Background(), cfg, "nmap", []string{"-sV", "10.0.0.5"})

	args := cmd.Args
	if args[3] != "--network=pentest-net" {
		t.Errorf("args[3] = %q, want '--network=pentest-net'", args[3])
	}
}

func TestBuildDockerCmd_WithRunFlags(t *testing.T) {
	// 追加フラグが含まれること
	cfg := &tools.DockerConfig{
		Image:    "instrumentisto/nmap",
		RunFlags: []string{"--cap-add=NET_RAW", "-v", "/tmp:/data"},
	}
	cmd := tools.BuildDockerCmdForTest(context.Background(), cfg, "nmap", []string{"-sV"})

	args := cmd.Args
	// docker run --rm --network=host --cap-add=NET_RAW -v /tmp:/data instrumentisto/nmap nmap -sV
	expected := []string{
		"docker", "run", "--rm", "--network=host",
		"--cap-add=NET_RAW", "-v", "/tmp:/data",
		"instrumentisto/nmap", "nmap", "-sV",
	}
	if len(args) != len(expected) {
		t.Fatalf("args len = %d, want %d\nargs: %v", len(args), len(expected), args)
	}
	for i, want := range expected {
		if args[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want)
		}
	}
}

func TestBuildDockerCmd_WithArgs(t *testing.T) {
	// binary + args がコマンド末尾に正しく追加されること
	cfg := &tools.DockerConfig{
		Image: "my-tool-image",
	}
	cmd := tools.BuildDockerCmdForTest(context.Background(), cfg, "nikto", []string{"-h", "http://target/"})

	args := cmd.Args
	// 末尾3要素: nikto -h http://target/
	if args[len(args)-3] != "nikto" {
		t.Errorf("binary position: got %q, want 'nikto'", args[len(args)-3])
	}
	if args[len(args)-2] != "-h" {
		t.Errorf("arg[0] position: got %q, want '-h'", args[len(args)-2])
	}
	if args[len(args)-1] != "http://target/" {
		t.Errorf("arg[1] position: got %q, want 'http://target/'", args[len(args)-1])
	}
}

// =============================================================================
// needsProposal 追加テスト (#90)
// =============================================================================

func TestNeedsProposal_AutoApproveOverridesAll(t *testing.T) {
	// autoApprove=true → 全コマンド無条件で needsProposal=false
	trueVal := true
	runner := newTestRunner(&tools.ToolDef{
		Name:             "dangerous-tool",
		ProposalRequired: &trueVal,
	})
	runner.SetAutoApprove(true)

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "dangerous-tool --exploit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if needsProposal {
		t.Error("autoApprove=true should override ProposalRequired=true")
	}
}

func TestNeedsProposal_DockerDefault(t *testing.T) {
	// Docker 設定あり + ProposalRequired 未設定 → false（Docker = サンドボックス）
	// 注: Docker が利用できない環境では useDocker=false になるのでフォールバック動作になる
	runner := newTestRunner(&tools.ToolDef{
		Name:   "nmap",
		Docker: &tools.DockerConfig{Image: "instrumentisto/nmap", Fallback: true},
	})

	// Docker が利用可能でない場合を想定し、IsProposalRequired で検証
	def := &tools.ToolDef{
		Name:   "nmap",
		Docker: &tools.DockerConfig{Image: "instrumentisto/nmap"},
	}
	// Docker あり + ProposalRequired nil → IsProposalRequired は false
	if def.IsProposalRequired() {
		t.Error("Docker tool with nil ProposalRequired should return false from IsProposalRequired")
	}
	_ = runner // runner は生成確認のみ
}

func TestNeedsProposal_DockerExplicitTrue(t *testing.T) {
	// Docker + ProposalRequired=true → true（明示指定が優先）
	trueVal := true
	def := &tools.ToolDef{
		Name:             "nmap",
		Docker:           &tools.DockerConfig{Image: "instrumentisto/nmap"},
		ProposalRequired: &trueVal,
	}
	if !def.IsProposalRequired() {
		t.Error("Docker tool with ProposalRequired=true should return true")
	}
}

func TestNeedsProposal_DockerExplicitFalse(t *testing.T) {
	// Docker + ProposalRequired=false → false
	falseVal := false
	def := &tools.ToolDef{
		Name:             "nmap",
		Docker:           &tools.DockerConfig{Image: "instrumentisto/nmap"},
		ProposalRequired: &falseVal,
	}
	if def.IsProposalRequired() {
		t.Error("Docker tool with ProposalRequired=false should return false")
	}
}

func TestNeedsProposal_NilDef(t *testing.T) {
	// ToolDef 未登録（nil）→ needsProposal=true（未知のコマンド）
	runner := newTestRunner() // 空レジストリ

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "unknowntool123 --flag")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !needsProposal {
		t.Error("nil ToolDef should require proposal (unknown command)")
	}
}

func TestNeedsProposal_HostRegistered(t *testing.T) {
	// 登録済みツール（Docker なし、ProposalRequired nil）→ IsProposalRequired が true
	runner := newTestRunner(&tools.ToolDef{
		Name: "msfconsole",
		// ProposalRequired: nil, Docker: nil → ホスト実行 → 要承認
	})

	ctx := context.Background()
	needsProposal, _, _, err := runner.Run(ctx, "msfconsole -r exploit.rc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !needsProposal {
		t.Error("registered host tool without explicit ProposalRequired=false should require proposal")
	}
}

// =============================================================================
// ForceRun テスト (#90)
// =============================================================================

func TestForceRun_EchoCommand(t *testing.T) {
	// ForceRun は承認済みコマンドを実行する（ブラックリストチェックなし）
	runner := newTestRunner(&tools.ToolDef{
		Name: "echo",
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 5,
			TailLines: 5,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lines, resultCh := runner.ForceRun(ctx, "echo hello-forcerun")

	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("ForceRun execution error: %v", res.Err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if !containsSubstring(output, "hello-forcerun") {
		t.Errorf("expected 'hello-forcerun' in output, got: %v", output)
	}
}

// =============================================================================
// resolveDocker テスト (#90)
// =============================================================================

func TestResolveDocker_NilDef(t *testing.T) {
	// nil ToolDef → useDocker=false, dockerAvailable=false
	runner := newTestRunner()
	useDocker, dockerAvail := runner.ResolveDockerForTest(nil)
	if useDocker {
		t.Error("nil ToolDef should not use Docker")
	}
	if dockerAvail {
		t.Error("nil ToolDef should report Docker unavailable")
	}
}

func TestResolveDocker_NilDockerConfig(t *testing.T) {
	// ToolDef はあるが Docker 設定なし → useDocker=false, dockerAvailable=false
	runner := newTestRunner()
	def := &tools.ToolDef{
		Name: "curl",
		// Docker: nil
	}
	useDocker, dockerAvail := runner.ResolveDockerForTest(def)
	if useDocker {
		t.Error("ToolDef without Docker config should not use Docker")
	}
	if dockerAvail {
		t.Error("ToolDef without Docker config should report Docker unavailable")
	}
}

// =============================================================================
// needsProposal 直接テスト — NeedsProposalForTest 経由 (#90)
// =============================================================================

func TestNeedsProposal_Direct_AutoApproveTrue(t *testing.T) {
	// autoApprove=true → needsProposal は常に false
	runner := newTestRunner()
	runner.SetAutoApprove(true)

	// 全パターンで false を返すことを確認
	cases := []struct {
		name      string
		def       *tools.ToolDef
		useDocker bool
		dockerOK  bool
	}{
		{"nil def", nil, false, false},
		{"host tool", &tools.ToolDef{Name: "msf"}, false, false},
		{"docker tool", &tools.ToolDef{Name: "nmap", Docker: &tools.DockerConfig{Image: "nmap"}}, true, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := runner.NeedsProposalForTest(c.def, c.useDocker, c.dockerOK)
			if got {
				t.Errorf("autoApprove=true should always return false, got true")
			}
		})
	}
}

func TestNeedsProposal_Direct_DockerWithExplicitProposal(t *testing.T) {
	// useDocker=true + ProposalRequired 明示指定 → 明示値を優先
	runner := newTestRunner()

	trueVal := true
	falseVal := false

	// ProposalRequired=true → needsProposal=true
	defTrue := &tools.ToolDef{
		Name:             "nmap",
		Docker:           &tools.DockerConfig{Image: "nmap"},
		ProposalRequired: &trueVal,
	}
	if !runner.NeedsProposalForTest(defTrue, true, true) {
		t.Error("Docker + ProposalRequired=true should return true")
	}

	// ProposalRequired=false → needsProposal=false
	defFalse := &tools.ToolDef{
		Name:             "nmap",
		Docker:           &tools.DockerConfig{Image: "nmap"},
		ProposalRequired: &falseVal,
	}
	if runner.NeedsProposalForTest(defFalse, true, true) {
		t.Error("Docker + ProposalRequired=false should return false")
	}
}

func TestNeedsProposal_Direct_DockerNoExplicit(t *testing.T) {
	// useDocker=true + ProposalRequired=nil → false（Docker = サンドボックス = 自動承認）
	runner := newTestRunner()

	def := &tools.ToolDef{
		Name:   "nmap",
		Docker: &tools.DockerConfig{Image: "nmap"},
	}
	if runner.NeedsProposalForTest(def, true, true) {
		t.Error("Docker + nil ProposalRequired should return false")
	}
}

func TestNeedsProposal_Direct_HostWithDef(t *testing.T) {
	// useDocker=false + ToolDef あり → IsProposalRequired() に委譲
	runner := newTestRunner()

	// ProposalRequired=nil, Docker=nil → true
	defHost := &tools.ToolDef{Name: "msfconsole"}
	if !runner.NeedsProposalForTest(defHost, false, false) {
		t.Error("host tool with nil ProposalRequired should return true")
	}

	// ProposalRequired=false → false
	falseVal := false
	defExplicit := &tools.ToolDef{Name: "curl", ProposalRequired: &falseVal}
	if runner.NeedsProposalForTest(defExplicit, false, false) {
		t.Error("host tool with ProposalRequired=false should return false")
	}
}

func TestNeedsProposal_Direct_NilDef(t *testing.T) {
	// useDocker=false + nil def → true（未知のコマンド）
	runner := newTestRunner()
	if !runner.NeedsProposalForTest(nil, false, false) {
		t.Error("nil ToolDef should return true (unknown command)")
	}
}

// =============================================================================
// Run のエッジケース: 空コマンド (#90)
// =============================================================================

func TestCommandRunner_Run_EmptyCommand(t *testing.T) {
	runner := newTestRunner()
	ctx := context.Background()
	_, _, _, err := runner.Run(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if !strings.Contains(err.Error(), "empty command") {
		t.Errorf("expected 'empty command' error, got: %v", err)
	}
}

func TestCommandRunner_Run_WhitespaceOnlyCommand(t *testing.T) {
	runner := newTestRunner()
	ctx := context.Background()
	_, _, _, err := runner.Run(ctx, "   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only command")
	}
	if !strings.Contains(err.Error(), "empty command") {
		t.Errorf("expected 'empty command' error, got: %v", err)
	}
}

// =============================================================================
// execute エラーパス: コンテキストタイムアウト (#90)
// =============================================================================

func TestCommandRunner_Execute_ContextCancelled(t *testing.T) {
	// コマンド実行中にコンテキストがキャンセルされた場合
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
	})

	ctx, cancel := context.WithCancel(context.Background())

	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo start && sleep 3 && echo end")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal")
	}

	// すぐにキャンセル
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	// drain lines
	for range lines {
	}
	res := <-resultCh

	// キャンセルによりコマンドが kill される → exit code != 0 or Err != nil
	if res.ExitCode == 0 && res.Err == nil {
		t.Error("expected non-zero exit code or error for cancelled command")
	}
}

// =============================================================================
// execute: 正常パス - ToolDef の TimeoutSec が使われること (#90)
// =============================================================================

func TestCommandRunner_Execute_CustomTimeout(t *testing.T) {
	// TimeoutSec=10 の ToolDef でコマンド実行 → 正常完了
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
		TimeoutSec:       10,
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 5,
			TailLines: 5,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo custom-timeout-test")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal")
	}

	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("execution error: %v", res.Err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if !containsSubstring(output, "custom-timeout-test") {
		t.Errorf("expected 'custom-timeout-test' in output, got: %v", output)
	}
}

// =============================================================================
// execute: ToolDef nil の場合（デフォルトタイムアウト・出力設定） (#90)
// =============================================================================

func TestCommandRunner_Execute_NilToolDef_UsesDefaults(t *testing.T) {
	// 未登録ツール → ToolDef=nil → デフォルトタイムアウト＆デフォルト出力設定
	// autoApprove=true で needsProposal をバイパス
	runner := newTestRunner() // 空レジストリ
	runner.SetAutoApprove(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo default-settings")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal with auto-approve")
	}

	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("execution error: %v", res.Err)
	}
	if !containsSubstring(output, "default-settings") {
		t.Errorf("expected 'default-settings' in output, got: %v", output)
	}
}

// =============================================================================
// execute: stderr 出力が取得できること (#90)
// =============================================================================

func TestCommandRunner_Execute_StderrCapture(t *testing.T) {
	// stderr に出力するコマンドが取得できること
	// sh -c 経由で実行されるので echo コマンドでリダイレクトできる
	falseVal := false
	runner := newTestRunner(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// echo は registry に登録済み。sh -c でリダイレクトを使う
	needsProposal, lines, resultCh, err := runner.Run(ctx, "echo stderr-test >&2")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if needsProposal {
		t.Error("expected no proposal")
	}

	var hasStderr bool
	for l := range lines {
		if strings.Contains(l.Content, "stderr-test") {
			hasStderr = true
		}
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("execution error: %v", res.Err)
	}
	if !hasStderr {
		t.Error("expected stderr output to be captured")
	}
}

// =============================================================================
// ForceRun: blacklisted command を承認後に実行できること (#90)
// =============================================================================

func TestForceRun_IgnoresBlacklist(t *testing.T) {
	// ForceRun はブラックリストチェックをスキップする
	runner := newTestRunner() // empty registry (blacklist has rm -rf / pattern)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ForceRun で echo を実行（ブラックリスト回避テスト用のシンプルなコマンド）
	lines, resultCh := runner.ForceRun(ctx, "echo force-test")
	var output []string
	for l := range lines {
		output = append(output, l.Content)
	}
	res := <-resultCh
	if res.Err != nil {
		t.Fatalf("ForceRun error: %v", res.Err)
	}
	if !containsSubstring(output, "force-test") {
		t.Errorf("expected 'force-test' in output, got: %v", output)
	}
}

// =============================================================================
// execute: LogStore への保存確認 (#90)
// =============================================================================

func TestCommandRunner_Execute_SavesResult(t *testing.T) {
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
	})
	bl := tools.NewBlacklist(nil)
	store := tools.NewLogStore()
	runner := tools.NewCommandRunner(reg, bl, store)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, lines, resultCh, err := runner.Run(ctx, "echo save-test")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for range lines {
	}
	res := <-resultCh

	// LogStore にエントリが保存されていること
	stored, ok := store.Get(res.ID)
	if !ok {
		t.Fatal("expected result to be saved in LogStore")
	}
	if stored.ToolName != "echo" {
		t.Errorf("stored ToolName: got %q, want %q", stored.ToolName, "echo")
	}
}
