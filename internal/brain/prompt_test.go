package brain

import (
	"strings"
	"testing"
)

func TestBuildSystemPrompt_WithToolNames(t *testing.T) {
	prompt := buildSystemPrompt([]string{"nmap", "nikto", "curl"}, nil)

	if !strings.Contains(prompt, "Registered tools: nmap, nikto, curl") {
		t.Error("expected registered tool names in prompt")
	}
	if !strings.Contains(prompt, "You may also use any other tools") {
		t.Error("expected 'other tools' message in prompt")
	}
}

func TestBuildSystemPrompt_Empty(t *testing.T) {
	prompt := buildSystemPrompt(nil, nil)

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
	prompt := buildSystemPrompt(nil, nil)

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
	prompt := buildSystemPrompt(nil, nil)

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
	prompt := buildSystemPrompt(nil, nil)

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
	prompt := buildSystemPrompt(nil, mcpTools)

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
	prompt := buildSystemPrompt(nil, nil)
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
