package brain

import (
	"strings"
	"testing"
)

func TestBuildSystemPrompt_WithToolNames(t *testing.T) {
	prompt := buildSystemPrompt([]string{"nmap", "nikto", "curl"})

	if !strings.Contains(prompt, "Registered tools: nmap, nikto, curl") {
		t.Error("expected registered tool names in prompt")
	}
	if !strings.Contains(prompt, "You may also use any other tools") {
		t.Error("expected 'other tools' message in prompt")
	}
}

func TestBuildSystemPrompt_Empty(t *testing.T) {
	prompt := buildSystemPrompt(nil)

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
	prompt := buildSystemPrompt(nil)

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
