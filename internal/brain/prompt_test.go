package brain

import (
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/pkg/schema"
)

func TestBuildSystemPrompt_WithToolNames(t *testing.T) {
	prompt := buildSystemPrompt([]string{"nmap", "nikto", "curl"}, nil, false)

	if !strings.Contains(prompt, "Registered tools: nmap, nikto, curl") {
		t.Error("expected registered tool names in prompt")
	}
	if !strings.Contains(prompt, "You may also use any other tools") {
		t.Error("expected 'other tools' message in prompt")
	}
}

func TestBuildSystemPrompt_Empty(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if strings.Contains(prompt, "Registered tools:") {
		t.Error("expected no 'Registered tools:' line when tool list is empty")
	}
	if !strings.Contains(prompt, "You may also use any other tools") {
		t.Error("expected 'other tools' message even when list is empty")
	}
}

func TestBuildPrompt_UserMessagePriority(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		UserMessage:    "vsftpdを攻撃して",
	})

	if !strings.Contains(prompt, "PRIORITY") {
		t.Error("expected PRIORITY label when user message is present")
	}
	if !strings.Contains(prompt, "Address the professional") {
		t.Error("expected priority instruction when user message is present")
	}
}

func TestBuildPrompt_NoUserMessage_DefaultInstruction(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
	})

	if strings.Contains(prompt, "PRIORITY") {
		t.Error("should not have PRIORITY label when no user message")
	}
	if !strings.Contains(prompt, "Determine the next security assessment action") {
		t.Error("expected default instruction when no user message")
	}
}

func TestSystemPrompt_ContainsUserInteraction(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "USER INTERACTION") {
		t.Error("system prompt should contain USER INTERACTION section")
	}
	if !strings.Contains(prompt, "always takes priority") {
		t.Error("system prompt should emphasize user message priority")
	}
}

func TestBuildPrompt_WithLastCommand(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		ToolOutput:     "PORT 22/tcp open ssh",
		LastCommand:    "nmap -sV 10.0.0.5",
		LastExitCode:   0,
	}
	prompt := buildPrompt(input)

	if !strings.Contains(prompt, "## Last Command") {
		t.Error("expected '## Last Command' section in prompt")
	}
	if !strings.Contains(prompt, "`nmap -sV 10.0.0.5`") {
		t.Error("expected the command string in backticks")
	}
	if !strings.Contains(prompt, "exit code: 0") {
		t.Error("expected exit code in prompt")
	}

	// Last Command は Target State の後、Last Assessment Output の前に出るべき
	cmdIdx := strings.Index(prompt, "## Last Command")
	outputIdx := strings.Index(prompt, "## Last Assessment Output")
	targetIdx := strings.Index(prompt, "## Authorized Target State")
	if cmdIdx <= targetIdx {
		t.Error("Last Command should appear after Target State")
	}
	if outputIdx >= 0 && cmdIdx >= outputIdx {
		t.Error("Last Command should appear before Last Assessment Output")
	}
}

func TestBuildPrompt_WithLastCommand_NonZeroExit(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		LastCommand:    "nmap -sV 10.0.0.5",
		LastExitCode:   1,
	}
	prompt := buildPrompt(input)

	if !strings.Contains(prompt, "exit code: 1") {
		t.Error("expected exit code 1 in prompt")
	}
}

func TestBuildPrompt_WithCommandHistory(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		CommandHistory: "1. `nmap -sV 10.0.0.5` → exit 0\n2. `nikto -h 10.0.0.5` → exit 1\n",
	}
	prompt := buildPrompt(input)

	if !strings.Contains(prompt, "## Recent Command History") {
		t.Error("expected '## Recent Command History' section in prompt")
	}
	if !strings.Contains(prompt, "nmap -sV 10.0.0.5") {
		t.Error("expected command history content in prompt")
	}
	if !strings.Contains(prompt, "nikto -h 10.0.0.5") {
		t.Error("expected second command in history")
	}
}

func TestBuildPrompt_NoHistory(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		ToolOutput:     "some output",
		UserMessage:    "scan the target",
	}
	prompt := buildPrompt(input)

	// 新しいセクションは出現しないはず
	if strings.Contains(prompt, "## Last Command") {
		t.Error("should not contain '## Last Command' when LastCommand is empty")
	}
	if strings.Contains(prompt, "## Recent Command History") {
		t.Error("should not contain '## Recent Command History' when CommandHistory is empty")
	}

	// 既存セクションは存在するはず
	if !strings.Contains(prompt, "## Authorized Target State") {
		t.Error("expected Target State section")
	}
	if !strings.Contains(prompt, "## Last Assessment Output") {
		t.Error("expected Last Assessment Output section")
	}
}

// --- parseActionJSON tests ---

func TestParseActionJSON_RawJSON(t *testing.T) {
	raw := `{"thought":"port 80 found","action":"run","command":"nmap -sV 10.0.0.5"}`
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON: %v", err)
	}
	if action.Thought != "port 80 found" {
		t.Errorf("Thought: got %q, want %q", action.Thought, "port 80 found")
	}
	if action.Action != "run" {
		t.Errorf("Action: got %q, want %q", action.Action, "run")
	}
	if action.Command != "nmap -sV 10.0.0.5" {
		t.Errorf("Command: got %q, want %q", action.Command, "nmap -sV 10.0.0.5")
	}
}

func TestParseActionJSON_MarkdownWrapped(t *testing.T) {
	raw := "```json\n{\"thought\":\"analyzing\",\"action\":\"think\"}\n```"
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (markdown wrapped): %v", err)
	}
	if action.Thought != "analyzing" {
		t.Errorf("Thought: got %q, want %q", action.Thought, "analyzing")
	}
	if action.Action != "think" {
		t.Errorf("Action: got %q, want %q", action.Action, "think")
	}
}

func TestParseActionJSON_MarkdownWrappedNoLang(t *testing.T) {
	raw := "```\n{\"thought\":\"checking\",\"action\":\"run\",\"command\":\"curl http://10.0.0.5/\"}\n```"
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (markdown wrapped no lang): %v", err)
	}
	if action.Action != "run" {
		t.Errorf("Action: got %q, want %q", action.Action, "run")
	}
	if action.Command != "curl http://10.0.0.5/" {
		t.Errorf("Command: got %q, want %q", action.Command, "curl http://10.0.0.5/")
	}
}

func TestParseActionJSON_EmptyString(t *testing.T) {
	_, err := parseActionJSON("")
	if err == nil {
		t.Error("expected error for empty string, got nil")
	}
}

func TestParseActionJSON_InvalidJSON(t *testing.T) {
	_, err := parseActionJSON("this is not json at all")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseActionJSON_MissingActionField(t *testing.T) {
	raw := `{"thought":"analyzing"}`
	_, err := parseActionJSON(raw)
	if err == nil {
		t.Error("expected error for JSON missing 'action' field, got nil")
	}
	if !strings.Contains(err.Error(), "missing 'action' field") {
		t.Errorf("error message should mention missing action field, got: %v", err)
	}
}

func TestParseActionJSON_WithLeadingTrailingWhitespace(t *testing.T) {
	raw := "   \n  {\"thought\":\"trimmed\",\"action\":\"think\"}  \n  "
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (whitespace): %v", err)
	}
	if action.Thought != "trimmed" {
		t.Errorf("Thought: got %q, want %q", action.Thought, "trimmed")
	}
	if action.Action != "think" {
		t.Errorf("Action: got %q, want %q", action.Action, "think")
	}
}

func TestParseActionJSON_WithProseBeforeJSON(t *testing.T) {
	// Some LLMs add prose text before the JSON
	raw := `Here is my analysis: {"thought":"found vuln","action":"memory","memory":{"type":"vulnerability","title":"CVE-2021-41773","description":"Path Traversal"}}`
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (prose before JSON): %v", err)
	}
	if action.Action != "memory" {
		t.Errorf("Action: got %q, want %q", action.Action, "memory")
	}
}

func TestBuildPrompt_WithTurnCount(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		TurnCount:      5,
	})
	if !strings.Contains(prompt, "## Turn") {
		t.Error("expected Turn section in prompt")
	}
	if !strings.Contains(prompt, "turn 5") {
		t.Error("expected turn number in prompt")
	}
	// 10以下なので警告なし
	if strings.Contains(prompt, "autonomously for many turns") {
		t.Error("should not show autonomy warning for turn 5")
	}
}

func TestBuildPrompt_HighTurnCount_AutonomyWarning(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		TurnCount:      15,
	})
	if !strings.Contains(prompt, "autonomously for many turns") {
		t.Error("expected autonomy warning for turn > 10")
	}
}

func TestBuildPrompt_ZeroTurnCount_NoSection(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		TurnCount:      0,
	})
	if strings.Contains(prompt, "## Turn") {
		t.Error("should not contain Turn section when TurnCount is 0")
	}
}

func TestParseActionJSON_EmptyActionField(t *testing.T) {
	raw := `{"thought":"analyzing","action":"","command":"nmap 10.0.0.5"}`
	_, err := parseActionJSON(raw)
	if err == nil {
		t.Error("expected error for empty action field, got nil")
	}
}

func TestParseActionJSON_WithMemoryAction(t *testing.T) {
	raw := `{"thought":"found credential","action":"memory","memory":{"type":"credential","title":"SSH Key","description":"Found SSH private key"}}`
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (memory): %v", err)
	}
	if action.Action != "memory" {
		t.Errorf("Action: got %q, want %q", action.Action, "memory")
	}
	if action.Memory == nil {
		t.Fatal("Memory should not be nil")
	}
	if action.Memory.Type != "credential" {
		t.Errorf("Memory.Type: got %q, want %q", action.Memory.Type, "credential")
	}
}

func TestBuildPrompt_WithMemory(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		Memory:         "[vulnerability] CVE-2021-41773: Apache 2.4.49 Path Traversal (critical)",
	}
	prompt := buildPrompt(input)

	if !strings.Contains(prompt, "## Previous Findings (from memory)") {
		t.Error("expected '## Previous Findings (from memory)' section in prompt")
	}
	if !strings.Contains(prompt, "CVE-2021-41773") {
		t.Error("expected memory content in prompt")
	}

	// Previous Findings は Target State の後、Last Command の前に出るべき
	targetIdx := strings.Index(prompt, "## Authorized Target State")
	memoryIdx := strings.Index(prompt, "## Previous Findings")
	if memoryIdx <= targetIdx {
		t.Error("Previous Findings should appear after Target State")
	}
}

func TestBuildPrompt_WithoutMemory(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		Memory:         "",
	}
	prompt := buildPrompt(input)

	if strings.Contains(prompt, "## Previous Findings") {
		t.Error("should not contain '## Previous Findings' when Memory is empty")
	}
}

func TestBuildPrompt_MemoryBeforeLastCommand(t *testing.T) {
	input := Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		Memory:         "[note] Open ports: 22, 80, 443",
		LastCommand:    "nmap -sV 10.0.0.5",
		LastExitCode:   0,
		ToolOutput:     "PORT 22/tcp open ssh",
	}
	prompt := buildPrompt(input)

	memoryIdx := strings.Index(prompt, "## Previous Findings")
	cmdIdx := strings.Index(prompt, "## Last Command")
	if memoryIdx < 0 {
		t.Fatal("expected Previous Findings section")
	}
	if cmdIdx < 0 {
		t.Fatal("expected Last Command section")
	}
	if memoryIdx >= cmdIdx {
		t.Error("Previous Findings should appear before Last Command")
	}
}

func TestSystemPrompt_ContainsMemoryEnforcement(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "ALWAYS use \"memory\" action to record key findings") {
		t.Error("system prompt should contain memory recording enforcement")
	}
	if !strings.Contains(prompt, "Do NOT repeat a scan if its results are already in the Previous Findings") {
		t.Error("system prompt should prohibit redundant scans")
	}
	if !strings.Contains(prompt, "Check Previous Findings before running any command") {
		t.Error("system prompt should instruct checking previous findings")
	}
}

func TestSystemPrompt_ContainsLanguageAdaptation(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "LANGUAGE:") {
		t.Error("system prompt should contain LANGUAGE section")
	}
	if !strings.Contains(prompt, "ALWAYS match the language of the user's input") {
		t.Error("system prompt should contain language adaptation instruction")
	}
}

func TestBuildPrompt_NonASCII_LanguageHint(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		UserMessage:    "vsftpdを攻撃して",
	})

	if !strings.Contains(prompt, "non-English language") {
		t.Error("expected non-English language hint for Japanese user message")
	}
	if !strings.Contains(prompt, "SAME language") {
		t.Error("expected SAME language instruction for non-ASCII user message")
	}
}

func TestBuildPrompt_ASCII_NoLanguageHint(t *testing.T) {
	prompt := buildPrompt(Input{
		TargetSnapshot: `{"host":"10.0.0.5"}`,
		UserMessage:    "scan the target",
	})

	if strings.Contains(prompt, "non-English language") {
		t.Error("should not contain non-English language hint for ASCII user message")
	}
}

func TestHasNonASCII(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello world", false},
		{"nmap -sV 10.0.0.5", false},
		{"vsftpdを攻撃して", true},
		{"日本語テスト", true},
		{"café", true},
		{"", false},
	}
	for _, tt := range tests {
		got := hasNonASCII(tt.input)
		if got != tt.want {
			t.Errorf("hasNonASCII(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestBuildSystemPrompt_WithMCPTools(t *testing.T) {
	mcpTools := []MCPToolInfo{
		{
			Server:      "playwright",
			Name:        "browser_navigate",
			Description: "Navigate to URL",
			InputSchema: map[string]any{
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "URL to navigate to",
					},
				},
			},
		},
		{
			Server:      "playwright",
			Name:        "browser_click",
			Description: "Click an element",
		},
	}
	prompt := buildSystemPrompt(nil, mcpTools, false)

	if !strings.Contains(prompt, "MCP TOOLS:") {
		t.Error("expected MCP TOOLS section in prompt")
	}
	if !strings.Contains(prompt, "Server: playwright") {
		t.Error("expected server name in MCP section")
	}
	if !strings.Contains(prompt, "browser_navigate") {
		t.Error("expected tool name browser_navigate")
	}
	if !strings.Contains(prompt, "browser_click") {
		t.Error("expected tool name browser_click")
	}
	if !strings.Contains(prompt, "call_mcp") {
		t.Error("expected call_mcp action in MCP usage instructions")
	}
}

func TestBuildSystemPrompt_NoMCPTools(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)
	if strings.Contains(prompt, "MCP TOOLS:") {
		t.Error("should not contain MCP TOOLS section when no MCP tools")
	}
}

func TestParseActionJSON_CallMCP(t *testing.T) {
	raw := `{"thought":"navigating to login page","action":"call_mcp","mcp_server":"playwright","mcp_tool":"browser_navigate","mcp_args":{"url":"http://10.0.0.5/login"}}`
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (call_mcp): %v", err)
	}
	if action.Action != "call_mcp" {
		t.Errorf("Action: got %q, want %q", action.Action, "call_mcp")
	}
	if action.MCPServer != "playwright" {
		t.Errorf("MCPServer: got %q, want %q", action.MCPServer, "playwright")
	}
	if action.MCPTool != "browser_navigate" {
		t.Errorf("MCPTool: got %q, want %q", action.MCPTool, "browser_navigate")
	}
	url, ok := action.MCPArgs["url"].(string)
	if !ok || url != "http://10.0.0.5/login" {
		t.Errorf("MCPArgs.url: got %v, want http://10.0.0.5/login", action.MCPArgs["url"])
	}
}

func TestBuildSystemPrompt_ContainsAssessmentWorkflow(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "ASSESSMENT WORKFLOW") {
		t.Error("expected ASSESSMENT WORKFLOW section in main agent prompt")
	}
	// ワークフローの4ステップが含まれること
	for _, keyword := range []string{"RECORD", "ANALYZE", "PLAN", "EXECUTE"} {
		if !strings.Contains(prompt, keyword) {
			t.Errorf("ASSESSMENT WORKFLOW should contain %q step", keyword)
		}
	}
}

func TestBuildSystemPrompt_WorkflowRequiresSearchKnowledge(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	// ANALYZE ステップで search_knowledge の使用が必須であること
	if !strings.Contains(prompt, "search_knowledge") {
		t.Error("ASSESSMENT WORKFLOW ANALYZE step should require search_knowledge")
	}
}

func TestBuildSystemPrompt_WorkflowRequiresSearchsploit(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	// ANALYZE ステップで searchsploit の使用が必須であること
	if !strings.Contains(prompt, "searchsploit") {
		t.Error("ASSESSMENT WORKFLOW ANALYZE step should require searchsploit for exploit lookup")
	}
}

func TestBuildSystemPrompt_ContainsServicePriority(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "SERVICE PRIORITY") {
		t.Error("expected SERVICE PRIORITY section in main agent prompt")
	}
	// 非 Web サービスが Web より前にリストされていること
	for _, svc := range []string{"Database", "Authentication", "Remote access"} {
		if !strings.Contains(prompt, svc) {
			t.Errorf("SERVICE PRIORITY should list %q", svc)
		}
	}
}

func TestBuildSystemPrompt_PlanRequiresConcreteTools(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	// PLAN ステップで具体的なツール名を含む攻撃計画が必要であること
	if !strings.Contains(prompt, "numbered attack plan") {
		t.Error("PLAN step should require numbered attack plan with concrete tools")
	}
}

func TestBuildSystemPrompt_SubAgent_ExcludesServicePriority(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, true)

	if strings.Contains(prompt, "SERVICE PRIORITY") {
		t.Error("SubAgent prompt should NOT contain SERVICE PRIORITY")
	}
}

func TestBuildSystemPrompt_ContainsRestrictedActions(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "RESTRICTED ACTIONS") {
		t.Error("expected RESTRICTED ACTIONS section in main agent prompt")
	}
	if !strings.Contains(prompt, "hydra") {
		t.Error("RESTRICTED ACTIONS should mention hydra as example")
	}
}

func TestBuildSystemPrompt_ContainsStdinProhibition(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	if !strings.Contains(prompt, "STDIN PROHIBITION") {
		t.Error("expected STDIN PROHIBITION section in main agent prompt")
	}
}

func TestBuildSystemPrompt_SubAgent_ExcludesWorkflowAndRestricted(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, true)

	if strings.Contains(prompt, "ASSESSMENT WORKFLOW") {
		t.Error("SubAgent prompt should NOT contain ASSESSMENT WORKFLOW")
	}
	if strings.Contains(prompt, "RESTRICTED ACTIONS") {
		t.Error("SubAgent prompt should NOT contain RESTRICTED ACTIONS")
	}
	if strings.Contains(prompt, "STDIN PROHIBITION") {
		t.Error("SubAgent prompt should NOT contain STDIN PROHIBITION")
	}
}

func TestBuildSystemPrompt_ContainsSubTaskActions(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, false)

	// 新しいアクションタイプがプロンプトに含まれることを確認
	for _, keyword := range []string{"spawn_task", "wait", "kill_task"} {
		if !strings.Contains(prompt, keyword) {
			t.Errorf("expected system prompt to contain %q", keyword)
		}
	}

	// PARALLEL EXECUTION セクションが含まれることを確認
	if !strings.Contains(prompt, "PARALLEL EXECUTION") {
		t.Error("expected system prompt to contain PARALLEL EXECUTION section")
	}
}

// --- SubAgent プロンプト テスト ---

func TestBuildSystemPrompt_SubAgent_ExcludesSpawnTask(t *testing.T) {
	prompt := buildSystemPrompt([]string{"nmap", "nikto"}, nil, true)

	// SubAgent プロンプトに spawn_task / wait / kill_task が含まれないこと
	for _, keyword := range []string{"spawn_task", "wait", "kill_task"} {
		if strings.Contains(prompt, keyword) {
			t.Errorf("SubAgent prompt should NOT contain %q", keyword)
		}
	}

	// PARALLEL EXECUTION セクションが除外されていること
	if strings.Contains(prompt, "PARALLEL EXECUTION") {
		t.Error("SubAgent prompt should NOT contain PARALLEL EXECUTION section")
	}

	// propose, add_target, call_mcp も除外されていること
	for _, keyword := range []string{"propose", "add_target", "call_mcp"} {
		if strings.Contains(prompt, keyword) {
			t.Errorf("SubAgent prompt should NOT contain %q", keyword)
		}
	}

	// USER INTERACTION セクションが除外されていること
	if strings.Contains(prompt, "USER INTERACTION") {
		t.Error("SubAgent prompt should NOT contain USER INTERACTION section")
	}

	// MCP TOOLS セクションが除外されていること（mcpTools は無視される）
	if strings.Contains(prompt, "MCP TOOLS") {
		t.Error("SubAgent prompt should NOT contain MCP TOOLS section")
	}
}

func TestBuildSystemPrompt_SubAgent_IncludesRunMemoryCompleteThink(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil, true)

	// SubAgent プロンプトに run, memory, complete, think が含まれること
	for _, keyword := range []string{"run", "memory", "complete", "think"} {
		if !strings.Contains(prompt, keyword) {
			t.Errorf("SubAgent prompt should contain %q", keyword)
		}
	}

	// STALL PREVENTION セクションが含まれること
	if !strings.Contains(prompt, "STALL PREVENTION") {
		t.Error("SubAgent prompt should contain STALL PREVENTION section")
	}

	// LANGUAGE セクションが含まれること
	if !strings.Contains(prompt, "LANGUAGE") {
		t.Error("SubAgent prompt should contain LANGUAGE section")
	}

	// SubAgent であることを示す識別子が含まれること
	if !strings.Contains(prompt, "SubAgent") {
		t.Error("SubAgent prompt should identify itself as a SubAgent")
	}
}

func TestBuildSystemPrompt_MainAgent_IncludesAll(t *testing.T) {
	prompt := buildSystemPrompt([]string{"nmap"}, nil, false)

	// MainAgent プロンプトには spawn_task が含まれる
	if !strings.Contains(prompt, "spawn_task") {
		t.Error("MainAgent prompt should contain spawn_task")
	}

	// MainAgent プロンプトには PARALLEL EXECUTION が含まれる
	if !strings.Contains(prompt, "PARALLEL EXECUTION") {
		t.Error("MainAgent prompt should contain PARALLEL EXECUTION")
	}

	// MainAgent プロンプトには USER INTERACTION が含まれる
	if !strings.Contains(prompt, "USER INTERACTION") {
		t.Error("MainAgent prompt should contain USER INTERACTION")
	}

	// MainAgent プロンプトには propose, add_target, call_mcp が含まれる
	for _, keyword := range []string{"propose", "add_target", "call_mcp"} {
		if !strings.Contains(prompt, keyword) {
			t.Errorf("MainAgent prompt should contain %q", keyword)
		}
	}
}

func TestBuildSystemPrompt_SubAgent_IgnoresMCPTools(t *testing.T) {
	mcpTools := []MCPToolInfo{
		{
			Server:      "playwright",
			Name:        "browser_navigate",
			Description: "Navigate to URL",
		},
	}
	prompt := buildSystemPrompt(nil, mcpTools, true)

	// SubAgent は mcpTools を無視する
	if strings.Contains(prompt, "MCP TOOLS") {
		t.Error("SubAgent prompt should NOT contain MCP TOOLS even when mcpTools are provided")
	}
	if strings.Contains(prompt, "playwright") {
		t.Error("SubAgent prompt should NOT contain MCP server names")
	}
}

func TestParseActionJSON_SpawnTask(t *testing.T) {
	raw := `{"thought":"spawn scan","action":"spawn_task","task_goal":"full scan","command":"nmap -sV -p- 10.0.0.5","task_port":0,"task_phase":"recon"}`
	action, err := parseActionJSON(raw)
	if err != nil {
		t.Fatalf("parseActionJSON (spawn_task): %v", err)
	}
	if action.Action != schema.ActionSpawnTask {
		t.Errorf("Action: got %q, want %q", action.Action, schema.ActionSpawnTask)
	}
	if action.TaskGoal != "full scan" {
		t.Errorf("TaskGoal: got %q, want %q", action.TaskGoal, "full scan")
	}
	if action.Command != "nmap -sV -p- 10.0.0.5" {
		t.Errorf("Command: got %q, want %q", action.Command, "nmap -sV -p- 10.0.0.5")
	}
	if action.TaskPhase != "recon" {
		t.Errorf("TaskPhase: got %q, want %q", action.TaskPhase, "recon")
	}
}
