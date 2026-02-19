package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

func TestSelectMode_ShowSelect(t *testing.T) {
	m := NewWithTargets(nil)

	options := []SelectOption{
		{Label: "Option A", Value: "a"},
		{Label: "Option B", Value: "b"},
	}

	m.showSelect("Choose:", options, nil)

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
	if len(m.selectOptions) != 2 {
		t.Errorf("expected 2 options, got %d", len(m.selectOptions))
	}
	if m.selectIndex != 0 {
		t.Error("expected initial index 0")
	}
	if m.selectTitle != "Choose:" {
		t.Errorf("expected title 'Choose:', got %q", m.selectTitle)
	}
}

func TestSelectMode_Navigation(t *testing.T) {
	m := NewWithTargets(nil)
	options := []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
		{Label: "C", Value: "c"},
	}
	m.showSelect("Test:", options, nil)

	// Down arrow should move to next option
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.selectIndex != 1 {
		t.Errorf("after down: expected index 1, got %d", m.selectIndex)
	}

	// Down again
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.selectIndex != 2 {
		t.Errorf("after 2x down: expected index 2, got %d", m.selectIndex)
	}

	// Down at bottom should stay at last index
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.selectIndex != 2 {
		t.Errorf("at bottom: expected index 2, got %d", m.selectIndex)
	}

	// Up arrow
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyUp})
	if m.selectIndex != 1 {
		t.Errorf("after up: expected index 1, got %d", m.selectIndex)
	}

	// Up again
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyUp})
	if m.selectIndex != 0 {
		t.Errorf("after 2x up: expected index 0, got %d", m.selectIndex)
	}

	// Up at top should stay at 0
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyUp})
	if m.selectIndex != 0 {
		t.Errorf("at top: expected index 0, got %d", m.selectIndex)
	}
}

func TestSelectMode_Escape(t *testing.T) {
	m := NewWithTargets(nil)
	options := []SelectOption{
		{Label: "A", Value: "a"},
	}
	m.showSelect("Test:", options, nil)

	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEscape})
	if m.inputMode != InputNormal {
		t.Error("escape should return to InputNormal mode")
	}
	if m.selectOptions != nil {
		t.Error("escape should clear selectOptions")
	}
	if m.selectCallback != nil {
		t.Error("escape should clear selectCallback")
	}
}

func TestSelectMode_Enter(t *testing.T) {
	m := NewWithTargets(nil)
	var selectedValue string
	options := []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
	}
	m.showSelect("Test:", options, func(m *Model, v string) {
		selectedValue = v
	})

	// Select second option
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	if selectedValue != "b" {
		t.Errorf("expected selected value 'b', got %q", selectedValue)
	}
	if m.inputMode != InputNormal {
		t.Error("enter should return to InputNormal mode")
	}
	if m.selectOptions != nil {
		t.Error("enter should clear selectOptions")
	}
}

func TestSelectMode_EnterFirstOption(t *testing.T) {
	m := NewWithTargets(nil)
	var selectedValue string
	options := []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
	}
	m.showSelect("Test:", options, func(m *Model, v string) {
		selectedValue = v
	})

	// Press enter without navigating (first option selected by default)
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	if selectedValue != "a" {
		t.Errorf("expected selected value 'a', got %q", selectedValue)
	}
}

func TestSelectMode_NilCallback(t *testing.T) {
	m := NewWithTargets(nil)
	options := []SelectOption{
		{Label: "A", Value: "a"},
	}
	m.showSelect("Test:", options, nil)

	// Enter with nil callback should not panic
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	if m.inputMode != InputNormal {
		t.Error("enter should return to InputNormal mode even with nil callback")
	}
}

func TestSelectMode_UpdateIntercepts(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	options := []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
	}
	m.showSelect("Test:", options, nil)

	// KeyDown in select mode should move the index, not affect other components
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	resultModel := result.(Model)

	if resultModel.selectIndex != 1 {
		t.Errorf("Update should intercept KeyDown in select mode: got index %d, want 1", resultModel.selectIndex)
	}

	// Escape should cancel select mode
	result, _ = resultModel.Update(tea.KeyMsg{Type: tea.KeyEscape})
	resultModel = result.(Model)

	if resultModel.inputMode != InputNormal {
		t.Error("Update should intercept Escape in select mode")
	}
}

func TestApproveCommand_NoArgs_ShowsSelect(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve")

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode for /approve, got %d", m.inputMode)
	}
	if len(m.selectOptions) != 2 {
		t.Errorf("expected 2 options (ON/OFF), got %d", len(m.selectOptions))
	}
}

func TestApproveCommand_WithArgs_StillWorks(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	// /approve on should still work directly (backward compat)
	m.handleApproveCommand("/approve on")

	if !runner.AutoApprove() {
		t.Error("expected auto-approve to be enabled via direct text")
	}
	// Should NOT enter select mode
	if m.inputMode == InputSelect {
		t.Error("/approve on should not enter select mode")
	}
}

func TestApproveCommand_SelectCallback_On(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve")

	// Simulate selecting "ON" (first option)
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	if !runner.AutoApprove() {
		t.Error("expected auto-approve ON after selecting first option")
	}
	if m.inputMode != InputNormal {
		t.Error("expected return to InputNormal after selection")
	}
}

func TestApproveCommand_SelectCallback_Off(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	runner.SetAutoApprove(true)
	m.Runner = runner

	m.handleApproveCommand("/approve")

	// Simulate selecting "OFF" (second option)
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyDown})
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	if runner.AutoApprove() {
		t.Error("expected auto-approve OFF after selecting second option")
	}
}

func TestModelCommand_NoArgs_ShowsProviderSelect(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "sk-openai-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	m.handleModelCommand("/model")

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode for /model, got %d", m.inputMode)
	}
	// Should have at least 1 provider option (anthropic)
	if len(m.selectOptions) < 1 {
		t.Errorf("expected at least 1 provider option, got %d", len(m.selectOptions))
	}
	if m.selectTitle != "Select provider:" {
		t.Errorf("expected provider select title, got %q", m.selectTitle)
	}
}

func TestModelCommand_ProviderThenModelSelect(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	var finalHint brain.ConfigHint
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		finalHint = hint
		return nil, nil
	}

	m.handleModelCommand("/model")

	// Step 1: Provider select should be showing
	if m.inputMode != InputSelect {
		t.Fatal("expected InputSelect mode for provider selection")
	}

	// Select anthropic (first option)
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	// Step 2: Should now show model select (not return to normal)
	if m.inputMode != InputSelect {
		t.Fatal("expected InputSelect mode for model selection after provider")
	}
	if m.selectTitle != "Select model (anthropic):" {
		t.Errorf("expected model select title, got %q", m.selectTitle)
	}
	// Should have model options
	if len(m.selectOptions) < 2 {
		t.Errorf("expected at least 2 model options for anthropic, got %d", len(m.selectOptions))
	}

	// Select a model
	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyEnter})

	// Should now be back to normal mode
	if m.inputMode != InputNormal {
		t.Error("expected InputNormal after model selection")
	}
	// BrainFactory should have been called with both provider and model
	if finalHint.Provider != brain.ProviderAnthropic {
		t.Errorf("expected anthropic provider, got %q", finalHint.Provider)
	}
	if finalHint.Model == "" {
		t.Error("expected non-empty model after two-step selection")
	}
}

func TestModelModels_ReturnsModelsForProvider(t *testing.T) {
	anthropicModels := modelsForProvider(brain.ProviderAnthropic)
	if len(anthropicModels) == 0 {
		t.Error("expected anthropic models to be non-empty")
	}
	// Check that claude-sonnet-4-6 is included
	found := false
	for _, m := range anthropicModels {
		if m.Value == "claude-sonnet-4-6" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected claude-sonnet-4-6 in anthropic models")
	}

	openaiModels := modelsForProvider(brain.ProviderOpenAI)
	if len(openaiModels) == 0 {
		t.Error("expected openai models to be non-empty")
	}

	ollamaModels := modelsForProvider(brain.ProviderOllama)
	if len(ollamaModels) == 0 {
		t.Error("expected ollama models to be non-empty")
	}
}

func TestModelCommand_WithArgs_StillWorks(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	factoryCalled := false
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		factoryCalled = true
		return nil, nil
	}

	m.handleModelCommand("/model openai/gpt-4o")

	if !factoryCalled {
		t.Error("expected BrainFactory to be called with direct args")
	}
	// Should NOT enter select mode
	if m.inputMode == InputSelect {
		t.Error("/model openai/gpt-4o should not enter select mode")
	}
}

func TestModelCommand_NoProviders_NoSelect(t *testing.T) {
	// Clear all provider env vars
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	m.handleModelCommand("/model")

	// No providers available → should log message, not show select
	if m.inputMode == InputSelect {
		t.Error("should not show select when no providers are available")
	}
}

func TestRenderSelectBar(t *testing.T) {
	m := NewWithTargets(nil)
	m.width = 80
	m.handleResize(80, 40)
	m.ready = true

	options := []SelectOption{
		{Label: "Option A", Value: "a"},
		{Label: "Option B", Value: "b"},
	}
	m.showSelect("Choose:", options, nil)

	output := m.renderSelectBar()

	// Should contain the title
	if output == "" {
		t.Error("renderSelectBar should not return empty string")
	}
}
