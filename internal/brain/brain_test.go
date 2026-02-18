package brain_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// mockAnthropicServer は Anthropic Messages API の最低限のモックを提供する。
func mockAnthropicServer(t *testing.T, responseJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 認証ヘッダーの確認（x-api-key または Authorization: Bearer）
		apiKey := r.Header.Get("x-api-key")
		authBearer := r.Header.Get("Authorization")
		if apiKey == "" && authBearer == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseJSON)) //nolint:errcheck // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- テスト専用 httptest サーバー、ブラウザ向け HTML ではなくハードコード JSON を返すのみ
	}))
}

// mockOpenAIServer は OpenAI Chat Completions API の最低限のモックを提供する。
func mockOpenAIServer(t *testing.T, responseJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseJSON)) //nolint:errcheck // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- テスト専用 httptest サーバー
	}))
}

// anthropicResponse は Anthropic API のレスポンス JSON を組み立てるヘルパー。
func anthropicResponse(actionJSON string) string {
	return `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "text", "text": "` + jsonEscape(actionJSON) + `"}],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 20}
	}`
}

// openAIResponse は OpenAI Chat Completions レスポンス JSON を組み立てるヘルパー。
func openAIResponse(actionJSON string) string {
	return `{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"choices": [{
			"index": 0,
			"message": {"role": "assistant", "content": "` + jsonEscape(actionJSON) + `"},
			"finish_reason": "stop"
		}],
		"usage": {"prompt_tokens": 10, "completion_tokens": 20}
	}`
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1]) // 前後の " を除去
}

// --- テストケース ---

func TestAnthropicBrain_Think_APIKey(t *testing.T) {
	action := `{"thought":"port 80 found","action":"run_tool","tool":"nikto","args":{"target":"10.0.0.5"}}`
	srv := mockAnthropicServer(t, anthropicResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-ant-test-key",
		BaseURL:  srv.URL, // テスト用にモックサーバーを向ける
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	result, err := b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5","open_ports":[{"port":80}]}`,
		ToolOutput:     "80/tcp open http Apache 2.4.49",
	})
	if err != nil {
		t.Fatalf("Think: %v", err)
	}

	if result.Action != schema.ActionRunTool {
		t.Errorf("Action: got %q, want %q", result.Action, schema.ActionRunTool)
	}
	if result.Tool != "nikto" {
		t.Errorf("Tool: got %q, want %q", result.Tool, "nikto")
	}
	if result.Thought == "" {
		t.Error("Thought should not be empty")
	}
}

func TestAnthropicBrain_Think_OAuthToken(t *testing.T) {
	action := `{"thought":"analyzing","action":"think"}`
	srv := mockAnthropicServer(t, anthropicResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthOAuthToken, // claude auth token の出力を使う
		Token:    "sk-ant-ocp01-test",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	result, err := b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err != nil {
		t.Fatalf("Think: %v", err)
	}
	if result.Action != schema.ActionThink {
		t.Errorf("Action: got %q, want %q", result.Action, schema.ActionThink)
	}
}

func TestOpenAIBrain_Think(t *testing.T) {
	action := `{"thought":"checking service","action":"run_tool","tool":"curl","args":{"url":"http://10.0.0.5/","flags":["-si"]}}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOpenAI,
		Model:    "gpt-4o",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-openai-test",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	result, err := b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
		ToolOutput:     "PORT   STATE SERVICE\n80/tcp open  http",
	})
	if err != nil {
		t.Fatalf("Think: %v", err)
	}
	if result.Tool != "curl" {
		t.Errorf("Tool: got %q, want %q", result.Tool, "curl")
	}
}

func TestBrain_New_EmptyToken_ReturnsError(t *testing.T) {
	_, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "", // トークンなし
	})
	if err == nil {
		t.Error("expected error for empty token, got nil")
	}
}

func TestBrain_New_UnknownProvider_ReturnsError(t *testing.T) {
	_, err := brain.New(brain.Config{
		Provider: "unknown-provider",
		Model:    "gpt-99",
		AuthType: brain.AuthAPIKey,
		Token:    "some-token",
	})
	if err == nil {
		t.Error("expected error for unknown provider, got nil")
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")

	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Token != "sk-ant-from-env" {
		t.Errorf("Token: got %q, want sk-ant-from-env", cfg.Token)
	}
	if cfg.AuthType != brain.AuthAPIKey {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthAPIKey)
	}
}

func TestLoadConfig_OAuthEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-ocp01-oauth")

	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Token != "sk-ant-ocp01-oauth" {
		t.Errorf("Token: got %q, want sk-ant-ocp01-oauth", cfg.Token)
	}
	if cfg.AuthType != brain.AuthOAuthToken {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthOAuthToken)
	}
}
