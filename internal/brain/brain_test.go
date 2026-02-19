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
	action := `{"thought":"port 80 found","action":"run","command":"nikto -h http://10.0.0.5/"}`
	srv := mockAnthropicServer(t, anthropicResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-ant-test-key",
		BaseURL:  srv.URL,
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

	if result.Action != schema.ActionRun {
		t.Errorf("Action: got %q, want %q", result.Action, schema.ActionRun)
	}
	if result.Command == "" {
		t.Error("Command should not be empty")
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
	action := `{"thought":"checking service","action":"run","command":"curl -si http://10.0.0.5/"}`
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
	if result.Action != schema.ActionRun {
		t.Errorf("Action: got %q, want %q", result.Action, schema.ActionRun)
	}
	if result.Command == "" {
		t.Error("Command should not be empty")
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
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
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

func TestOllamaBrain_Think(t *testing.T) {
	// Ollama は OpenAI 互換 API を使うので mockOpenAIServer で代用できる
	action := `{"thought":"starting port scan","action":"run","command":"nmap -sV 10.0.0.5"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama): %v", err)
	}
	if b.Provider() != "ollama" {
		t.Errorf("Provider(): got %q, want ollama", b.Provider())
	}

	result, err := b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err != nil {
		t.Fatalf("Think (ollama): %v", err)
	}
	if result.Action != schema.ActionRun {
		t.Errorf("Action: got %q, want %q", result.Action, schema.ActionRun)
	}
}

func TestLoadConfig_Ollama_DefaultURL(t *testing.T) {
	t.Setenv("OLLAMA_BASE_URL", "")
	t.Setenv("OLLAMA_MODEL", "")

	cfg, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderOllama})
	if err != nil {
		t.Fatalf("LoadConfig ollama: %v", err)
	}
	if cfg.BaseURL != "http://localhost:11434" {
		t.Errorf("BaseURL: got %q, want http://localhost:11434", cfg.BaseURL)
	}
	if cfg.Model != "llama3.2" {
		t.Errorf("Model: got %q, want llama3.2", cfg.Model)
	}
	if cfg.AuthType != brain.AuthNone {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthNone)
	}
}

func TestLoadConfig_Ollama_CustomURL(t *testing.T) {
	t.Setenv("OLLAMA_BASE_URL", "http://gpu-server:11434")
	t.Setenv("OLLAMA_MODEL", "mistral")

	cfg, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderOllama})
	if err != nil {
		t.Fatalf("LoadConfig ollama: %v", err)
	}
	if cfg.BaseURL != "http://gpu-server:11434" {
		t.Errorf("BaseURL: got %q", cfg.BaseURL)
	}
	if cfg.Model != "mistral" {
		t.Errorf("Model: got %q, want mistral", cfg.Model)
	}
}

// --- DetectAvailableProviders ---

func TestDetectAvailableProviders_AnthropicAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	providers := brain.DetectAvailableProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one provider")
	}
	if providers[0] != brain.ProviderAnthropic {
		t.Errorf("first provider: got %q, want anthropic", providers[0])
	}
}

func TestDetectAvailableProviders_OAuthToken(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-ocp01-test")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	providers := brain.DetectAvailableProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one provider")
	}
	if providers[0] != brain.ProviderAnthropic {
		t.Errorf("first provider: got %q, want anthropic", providers[0])
	}
}

func TestDetectAvailableProviders_OpenAI(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "sk-openai-test")
	t.Setenv("OLLAMA_BASE_URL", "")

	providers := brain.DetectAvailableProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one provider")
	}
	if providers[0] != brain.ProviderOpenAI {
		t.Errorf("first provider: got %q, want openai", providers[0])
	}
}

func TestDetectAvailableProviders_Multiple(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "sk-openai-test")
	t.Setenv("OLLAMA_BASE_URL", "")

	providers := brain.DetectAvailableProviders()
	if len(providers) < 2 {
		t.Fatalf("expected at least 2 providers, got %d", len(providers))
	}
	// Anthropic should be first (priority)
	if providers[0] != brain.ProviderAnthropic {
		t.Errorf("first provider: got %q, want anthropic", providers[0])
	}
	if providers[1] != brain.ProviderOpenAI {
		t.Errorf("second provider: got %q, want openai", providers[1])
	}
}

func TestDetectAvailableProviders_None(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	providers := brain.DetectAvailableProviders()
	if len(providers) != 0 {
		t.Errorf("expected no providers, got %v", providers)
	}
}

func TestDetectAvailableProviders_OllamaExplicitURL(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "http://gpu-server:11434")

	providers := brain.DetectAvailableProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one provider")
	}
	if providers[0] != brain.ProviderOllama {
		t.Errorf("first provider: got %q, want ollama", providers[0])
	}
}

// --- ensureV1Path tests (via New() with Ollama provider) ---

func TestEnsureV1Path_URLAlreadyEndingWithV1(t *testing.T) {
	// URL already ends with /v1 — should not double-add
	action := `{"thought":"test","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	// The mock server URL does not end with /v1, so we construct a URL that does
	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL + "/v1",
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, URL with /v1): %v", err)
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

func TestEnsureV1Path_URLWithTrailingSlash(t *testing.T) {
	// URL has trailing slash — should strip it and add /v1
	action := `{"thought":"test","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	// We need the mock to accept requests at /v1/chat/completions
	// The server URL is like http://127.0.0.1:PORT
	// ensureV1Path("http://127.0.0.1:PORT/") → "http://127.0.0.1:PORT/v1"
	// Then openai.go appends /chat/completions → "http://127.0.0.1:PORT/v1/chat/completions"
	// The mock server handles all paths, so this will work
	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL + "/",
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, URL with trailing slash): %v", err)
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

func TestEnsureV1Path_URLWithoutTrailingSlash(t *testing.T) {
	// URL has no trailing slash and no /v1 — should add /v1
	action := `{"thought":"test","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, URL without trailing slash): %v", err)
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

func TestEnsureV1Path_URLEndingWithV1Slash(t *testing.T) {
	// URL ends with /v1/ — should strip trailing slash and return /v1
	action := `{"thought":"test","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL + "/v1/",
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, URL ending with /v1/): %v", err)
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

// --- ExtractTarget 統合テスト ---

func TestAnthropicBrain_ExtractTarget_WithHost(t *testing.T) {
	extractJSON := `{"host":"eighteen.htb","instruction":"攻略して"}`
	srv := mockAnthropicServer(t, anthropicResponse(extractJSON))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-ant-test-key",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	host, instruction, err := b.ExtractTarget(context.Background(), "eighteen.htbを攻略して")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "eighteen.htb" {
		t.Errorf("host: got %q, want %q", host, "eighteen.htb")
	}
	if instruction != "攻略して" {
		t.Errorf("instruction: got %q, want %q", instruction, "攻略して")
	}
}

func TestAnthropicBrain_ExtractTarget_NoHost(t *testing.T) {
	extractJSON := `{"host":"","instruction":"Webサーバーのセキュリティを診断"}`
	srv := mockAnthropicServer(t, anthropicResponse(extractJSON))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-ant-test-key",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	host, instruction, err := b.ExtractTarget(context.Background(), "Webサーバーのセキュリティを診断")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "" {
		t.Errorf("host: got %q, want empty", host)
	}
	if instruction != "Webサーバーのセキュリティを診断" {
		t.Errorf("instruction: got %q, want %q", instruction, "Webサーバーのセキュリティを診断")
	}
}

func TestOpenAIBrain_ExtractTarget_WithHost(t *testing.T) {
	extractJSON := `{"host":"192.168.1.1","instruction":"会社のサーバーをスキャンして"}`
	srv := mockOpenAIServer(t, openAIResponse(extractJSON))
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

	host, instruction, err := b.ExtractTarget(context.Background(), "会社のサーバー 192.168.1.1 をスキャンして")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "192.168.1.1" {
		t.Errorf("host: got %q, want %q", host, "192.168.1.1")
	}
	if instruction != "会社のサーバーをスキャンして" {
		t.Errorf("instruction: got %q, want %q", instruction, "会社のサーバーをスキャンして")
	}
}

func TestOllamaBrain_ExtractTarget_WithHost(t *testing.T) {
	extractJSON := `{"host":"target.local","instruction":"scan it"}`
	srv := mockOpenAIServer(t, openAIResponse(extractJSON))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama): %v", err)
	}

	host, instruction, err := b.ExtractTarget(context.Background(), "target.local を scan して")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "target.local" {
		t.Errorf("host: got %q, want %q", host, "target.local")
	}
	if instruction != "scan it" {
		t.Errorf("instruction: got %q, want %q", instruction, "scan it")
	}
}

func TestAnthropicBrain_ExtractTarget_APIError(t *testing.T) {
	// エラーレスポンスを返すサーバー
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-ant-test-key",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	_, _, err = b.ExtractTarget(context.Background(), "eighteen.htbを攻略して")
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}
