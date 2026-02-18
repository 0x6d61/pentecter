package tools_test

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/tools"
)

func TestBuildCLIArgs_StringValue(t *testing.T) {
	tmpl := "{flags} -p {ports} {target}"
	args := map[string]any{
		"target": "10.0.0.5",
		"ports":  "21,22,80",
		"flags":  "-sV",
	}

	got, err := tools.BuildCLIArgs(tmpl, args)
	if err != nil {
		t.Fatalf("BuildCLIArgs: %v", err)
	}

	want := []string{"-sV", "-p", "21,22,80", "10.0.0.5"}
	assertStringSliceEqual(t, got, want)
}

func TestBuildCLIArgs_ArrayValue(t *testing.T) {
	tmpl := "{flags} {target}"
	args := map[string]any{
		"target": "10.0.0.5",
		"flags":  []any{"-sV", "-Pn", "--open"},
	}

	got, err := tools.BuildCLIArgs(tmpl, args)
	if err != nil {
		t.Fatalf("BuildCLIArgs: %v", err)
	}

	want := []string{"-sV", "-Pn", "--open", "10.0.0.5"}
	assertStringSliceEqual(t, got, want)
}

func TestBuildCLIArgs_MissingOptionalKey(t *testing.T) {
	// ports が args にない → "-p {ports}" トークングループを丸ごと除去
	tmpl := "{flags} -p {ports} {target}"
	args := map[string]any{
		"target": "10.0.0.5",
		"flags":  "-sV",
		// ports なし
	}

	got, err := tools.BuildCLIArgs(tmpl, args)
	if err != nil {
		t.Fatalf("BuildCLIArgs: %v", err)
	}

	// "-p" と ports が除去されて target と flags だけ残る
	if contains(got, "-p") {
		t.Errorf("expected -p to be removed when ports is missing, got: %v", got)
	}
	if !contains(got, "10.0.0.5") {
		t.Errorf("expected target to be present, got: %v", got)
	}
}

func TestBuildCLIArgs_NoTemplate_PassArgsAsIs(t *testing.T) {
	// args_template が空のとき: args の値をフラットに展開
	tmpl := ""
	args := map[string]any{
		"_args": []any{"-h", "10.0.0.5"},
	}

	got, err := tools.BuildCLIArgs(tmpl, args)
	if err != nil {
		t.Fatalf("BuildCLIArgs: %v", err)
	}

	want := []string{"-h", "10.0.0.5"}
	assertStringSliceEqual(t, got, want)
}

func TestBuildCLIArgs_RequiredKeyMissing_ReturnsError(t *testing.T) {
	// {target!} の ! は必須マーカー → なければエラー
	tmpl := "-sV {target!}"
	args := map[string]any{} // target なし

	_, err := tools.BuildCLIArgs(tmpl, args)
	if err == nil {
		t.Error("expected error for missing required key 'target', got nil")
	}
}

// --- ヘルパー ---

func assertStringSliceEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("len: got %d (%v), want %d (%v)", len(got), got, len(want), want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
