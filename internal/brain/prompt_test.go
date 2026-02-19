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
