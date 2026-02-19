package brain

import (
	"testing"
)

// --- parseExtractTargetResponse ユニットテスト ---

func TestParseExtractTargetResponse_WithHost(t *testing.T) {
	raw := `{"host":"eighteen.htb","instruction":"攻略して"}`
	host, instruction, err := parseExtractTargetResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "eighteen.htb" {
		t.Errorf("host: got %q, want %q", host, "eighteen.htb")
	}
	if instruction != "攻略して" {
		t.Errorf("instruction: got %q, want %q", instruction, "攻略して")
	}
}

func TestParseExtractTargetResponse_NoHost(t *testing.T) {
	raw := `{"host":"","instruction":"Webサーバーを診断"}`
	host, instruction, err := parseExtractTargetResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "" {
		t.Errorf("host: got %q, want empty", host)
	}
	if instruction != "Webサーバーを診断" {
		t.Errorf("instruction: got %q, want %q", instruction, "Webサーバーを診断")
	}
}

func TestParseExtractTargetResponse_CodeBlock(t *testing.T) {
	raw := "```json\n{\"host\":\"192.168.1.1\",\"instruction\":\"スキャンして\"}\n```"
	host, instruction, err := parseExtractTargetResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "192.168.1.1" {
		t.Errorf("host: got %q, want %q", host, "192.168.1.1")
	}
	if instruction != "スキャンして" {
		t.Errorf("instruction: got %q, want %q", instruction, "スキャンして")
	}
}

func TestParseExtractTargetResponse_WithSurroundingText(t *testing.T) {
	// LLM が JSON の前後にテキストを出力した場合
	raw := "Here is the extracted info:\n{\"host\":\"example.com\",\"instruction\":\"diagnose\"}\nDone."
	host, instruction, err := parseExtractTargetResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "example.com" {
		t.Errorf("host: got %q, want %q", host, "example.com")
	}
	if instruction != "diagnose" {
		t.Errorf("instruction: got %q, want %q", instruction, "diagnose")
	}
}

func TestParseExtractTargetResponse_InvalidJSON(t *testing.T) {
	raw := "this is not json at all"
	_, _, err := parseExtractTargetResponse(raw)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseExtractTargetResponse_IPAddress(t *testing.T) {
	raw := `{"host":"10.10.14.5","instruction":"会社のサーバーをスキャンして"}`
	host, instruction, err := parseExtractTargetResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "10.10.14.5" {
		t.Errorf("host: got %q, want %q", host, "10.10.14.5")
	}
	if instruction != "会社のサーバーをスキャンして" {
		t.Errorf("instruction: got %q, want %q", instruction, "会社のサーバーをスキャンして")
	}
}
