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

// --- Provider() テスト ---

func TestAnthropicBrain_Provider(t *testing.T) {
	// brain.New で anthropicBrain を生成し、Provider() が "anthropic" を返すことを確認。
	// モックサーバーは不要（Provider() はネットワークアクセスしない）。
	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-ant-test-provider",
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	got := b.Provider()
	if got != "anthropic" {
		t.Errorf("Provider(): got %q, want %q", got, "anthropic")
	}
}

func TestOpenAIBrain_Provider(t *testing.T) {
	// brain.New で openAIBrain を生成し、Provider() が "openai" を返すことを確認。
	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOpenAI,
		Model:    "gpt-4o",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-openai-test-provider",
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	got := b.Provider()
	if got != "openai" {
		t.Errorf("Provider(): got %q, want %q", got, "openai")
	}
}

func TestOllamaBrain_Provider(t *testing.T) {
	// Ollama は OpenAI 互換ラッパーだが Provider() は "ollama" を返すはず。
	// 既存の TestOllamaBrain_Think でも検証済みだが、明示的なテストとして追加。
	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  "http://localhost:11434",
	})
	if err != nil {
		t.Fatalf("brain.New (ollama): %v", err)
	}

	got := b.Provider()
	if got != "ollama" {
		t.Errorf("Provider(): got %q, want %q", got, "ollama")
	}
}

// =============================================================================
// parseAnthropicResponse エッジケース
// =============================================================================

// parseAnthropicResponse: 不正な JSON を渡すと unmarshal エラーになること。
func TestAnthropicBrain_Think_MalformedJSON(t *testing.T) {
	// サーバーが不正な JSON を返す場合
	srv := mockAnthropicServer(t, `{this is not valid json}`)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for malformed JSON response, got nil")
	}
}

// parseAnthropicResponse: content 配列が空の場合、"no text content" エラーになること。
func TestAnthropicBrain_Think_EmptyContent(t *testing.T) {
	// content 配列が空のレスポンス
	emptyContentResp := `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 0}
	}`
	srv := mockAnthropicServer(t, emptyContentResp)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for empty content array, got nil")
	}
}

// parseAnthropicResponse: content に text 以外のタイプ（例: tool_use）のみが含まれる場合。
func TestAnthropicBrain_Think_NonTextContentOnly(t *testing.T) {
	nonTextResp := `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "tool_use", "text": ""}],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 5}
	}`
	srv := mockAnthropicServer(t, nonTextResp)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error when content has only non-text blocks, got nil")
	}
}

// parseAnthropicResponse: text ブロック内の action JSON が不正な場合。
func TestAnthropicBrain_Think_InvalidActionJSON(t *testing.T) {
	// text ブロックはあるが、中身が有効な action JSON ではない
	invalidActionResp := anthropicResponse(`not a valid action json`)
	srv := mockAnthropicServer(t, invalidActionResp)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for invalid action JSON in text block, got nil")
	}
}

// parseAnthropicResponse: text ブロックに action フィールドがない場合。
func TestAnthropicBrain_Think_MissingActionField(t *testing.T) {
	missingAction := `{"thought":"analyzing"}`
	srv := mockAnthropicServer(t, anthropicResponse(missingAction))
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for missing action field, got nil")
	}
}

// =============================================================================
// parseOpenAIResponse エッジケース
// =============================================================================

// parseOpenAIResponse: 不正な JSON を渡すと unmarshal エラーになること。
func TestOpenAIBrain_Think_MalformedJSON(t *testing.T) {
	srv := mockOpenAIServer(t, `{not valid json at all}`)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for malformed JSON response, got nil")
	}
}

// parseOpenAIResponse: choices 配列が空の場合。
func TestOpenAIBrain_Think_EmptyChoices(t *testing.T) {
	emptyChoicesResp := `{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"choices": [],
		"usage": {"prompt_tokens": 10, "completion_tokens": 0}
	}`
	srv := mockOpenAIServer(t, emptyChoicesResp)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for empty choices, got nil")
	}
}

// parseOpenAIResponse: message.content 内のアクション JSON が不正な場合。
func TestOpenAIBrain_Think_InvalidActionJSON(t *testing.T) {
	invalidActionResp := openAIResponse(`this is not action json`)
	srv := mockOpenAIServer(t, invalidActionResp)
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for invalid action JSON in message content, got nil")
	}
}

// parseOpenAIResponse: message.content に action フィールドがない場合。
func TestOpenAIBrain_Think_MissingActionField(t *testing.T) {
	missingAction := `{"thought":"analyzing"}`
	srv := mockOpenAIServer(t, openAIResponse(missingAction))
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for missing action field, got nil")
	}
}

// =============================================================================
// Anthropic Think — API エラーパス
// =============================================================================

// Anthropic Think: API が非 200 ステータスを返す場合。
func TestAnthropicBrain_Think_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"too many requests"}}`))
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}

// Anthropic Think: コンテキストがキャンセルされた場合。
func TestAnthropicBrain_Think_ContextCanceled(t *testing.T) {
	// リクエストが来たらブロックするサーバー（キャンセルでエラーになるはず）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 即座にキャンセル

	_, err = b.Think(ctx, brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}

// =============================================================================
// OpenAI Think — API エラーパス
// =============================================================================

// OpenAI Think: API が非 200 ステータスを返す場合。
func TestOpenAIBrain_Think_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"internal server error"}}`))
	}))
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

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}

// OpenAI Think: コンテキストがキャンセルされた場合。
func TestOpenAIBrain_Think_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = b.Think(ctx, brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}

// =============================================================================
// ExtractTarget (Anthropic) エッジケース
// =============================================================================

// Anthropic ExtractTarget: レスポンスが不正な JSON の場合。
func TestAnthropicBrain_ExtractTarget_MalformedJSON(t *testing.T) {
	srv := mockAnthropicServer(t, `{invalid json}`)
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
		t.Error("expected error for malformed JSON response, got nil")
	}
}

// Anthropic ExtractTarget: content 配列が空の場合。
func TestAnthropicBrain_ExtractTarget_EmptyContent(t *testing.T) {
	emptyContentResp := `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 0}
	}`
	srv := mockAnthropicServer(t, emptyContentResp)
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
		t.Error("expected error for empty content array, got nil")
	}
}

// Anthropic ExtractTarget: content に text 以外のタイプのみ含まれる場合。
func TestAnthropicBrain_ExtractTarget_NonTextContentOnly(t *testing.T) {
	nonTextResp := `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "tool_use", "text": ""}],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 5}
	}`
	srv := mockAnthropicServer(t, nonTextResp)
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
		t.Error("expected error when content has only non-text blocks, got nil")
	}
}

// Anthropic ExtractTarget: text ブロック内の JSON が不正な場合。
func TestAnthropicBrain_ExtractTarget_InvalidTargetJSON(t *testing.T) {
	invalidTargetResp := anthropicResponse(`this is not valid extract target json`)
	srv := mockAnthropicServer(t, invalidTargetResp)
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
		t.Error("expected error for invalid target JSON in text block, got nil")
	}
}

// Anthropic ExtractTarget: コンテキストキャンセル。
func TestAnthropicBrain_ExtractTarget_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = b.ExtractTarget(ctx, "eighteen.htbを攻略して")
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}

// Anthropic ExtractTarget: OAuth 認証で成功する場合。
func TestAnthropicBrain_ExtractTarget_OAuthToken(t *testing.T) {
	extractJSON := `{"host":"ten.htb","instruction":"scan it"}`
	// OAuth 認証ヘッダーを検証するカスタムサーバー
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		beta := r.Header.Get("anthropic-beta")
		if beta == "" {
			http.Error(w, "missing anthropic-beta header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(anthropicResponse(extractJSON))) //nolint:errcheck // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- テスト専用 httptest サーバー
	}))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-sonnet-4-6",
		AuthType: brain.AuthOAuthToken,
		Token:    "sk-ant-ocp01-test",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	host, instruction, err := b.ExtractTarget(context.Background(), "ten.htbをスキャンして")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "ten.htb" {
		t.Errorf("host: got %q, want %q", host, "ten.htb")
	}
	if instruction != "scan it" {
		t.Errorf("instruction: got %q, want %q", instruction, "scan it")
	}
}

// =============================================================================
// ExtractTarget (OpenAI) エッジケース
// =============================================================================

// OpenAI ExtractTarget: API エラー（非 200）。
func TestOpenAIBrain_ExtractTarget_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad request"}}`))
	}))
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

	_, _, err = b.ExtractTarget(context.Background(), "192.168.1.1 をスキャンして")
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}

// OpenAI ExtractTarget: 不正な JSON レスポンス。
func TestOpenAIBrain_ExtractTarget_MalformedJSON(t *testing.T) {
	srv := mockOpenAIServer(t, `{invalid json}`)
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

	_, _, err = b.ExtractTarget(context.Background(), "192.168.1.1 をスキャンして")
	if err == nil {
		t.Error("expected error for malformed JSON response, got nil")
	}
}

// OpenAI ExtractTarget: choices 配列が空の場合。
func TestOpenAIBrain_ExtractTarget_EmptyChoices(t *testing.T) {
	emptyChoicesResp := `{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"choices": [],
		"usage": {"prompt_tokens": 10, "completion_tokens": 0}
	}`
	srv := mockOpenAIServer(t, emptyChoicesResp)
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

	_, _, err = b.ExtractTarget(context.Background(), "192.168.1.1 をスキャンして")
	if err == nil {
		t.Error("expected error for empty choices, got nil")
	}
}

// OpenAI ExtractTarget: message.content 内の target JSON が不正。
func TestOpenAIBrain_ExtractTarget_InvalidTargetJSON(t *testing.T) {
	invalidTargetResp := openAIResponse(`not a valid extract target json at all`)
	srv := mockOpenAIServer(t, invalidTargetResp)
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

	_, _, err = b.ExtractTarget(context.Background(), "192.168.1.1 をスキャンして")
	if err == nil {
		t.Error("expected error for invalid target JSON in message content, got nil")
	}
}

// OpenAI ExtractTarget: コンテキストキャンセル。
func TestOpenAIBrain_ExtractTarget_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = b.ExtractTarget(ctx, "192.168.1.1 をスキャンして")
	if err == nil {
		t.Error("expected error for canceled context, got nil")
	}
}

// =============================================================================
// LoadConfig エッジケース
// =============================================================================

// LoadConfig: Anthropic で全認証環境変数が未設定の場合のエラー。
func TestLoadConfig_Anthropic_NoCredentials(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")

	_, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderAnthropic})
	if err == nil {
		t.Error("expected error when no Anthropic credentials are set, got nil")
	}
}

// LoadConfig: Anthropic のデフォルトモデルが設定されること。
func TestLoadConfig_Anthropic_DefaultModel(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")

	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderAnthropic,
		// Model は空 → デフォルトが使われるはず
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Model == "" {
		t.Error("expected default model to be set for Anthropic")
	}
}

// LoadConfig: Anthropic で CLAUDE_CODE_OAUTH_TOKEN が設定されている場合。
func TestLoadConfig_Anthropic_ClaudeCodeOAuthToken(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-ocp01-claude-code")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")

	cfg, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderAnthropic})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Token != "sk-ant-ocp01-claude-code" {
		t.Errorf("Token: got %q, want sk-ant-ocp01-claude-code", cfg.Token)
	}
	if cfg.AuthType != brain.AuthOAuthToken {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthOAuthToken)
	}
}

// LoadConfig: Anthropic API KEY は OAuth より優先されること。
func TestLoadConfig_Anthropic_APIKeyPriority(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-apikey")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-ocp01-oauth")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-auth")

	cfg, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderAnthropic})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// API key が優先される
	if cfg.Token != "sk-ant-apikey" {
		t.Errorf("Token: got %q, want sk-ant-apikey (API key should take priority)", cfg.Token)
	}
	if cfg.AuthType != brain.AuthAPIKey {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthAPIKey)
	}
}

// LoadConfig: OpenAI で認証環境変数が未設定の場合のエラー。
func TestLoadConfig_OpenAI_NoCredentials(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")

	_, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderOpenAI})
	if err == nil {
		t.Error("expected error when no OpenAI credentials are set, got nil")
	}
}

// LoadConfig: OpenAI で認証環境変数が設定されている場合の成功パス。
func TestLoadConfig_OpenAI_Success(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-openai-from-env")

	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderOpenAI,
		Model:    "gpt-4o",
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Token != "sk-openai-from-env" {
		t.Errorf("Token: got %q, want sk-openai-from-env", cfg.Token)
	}
	if cfg.AuthType != brain.AuthAPIKey {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthAPIKey)
	}
}

// LoadConfig: 不明なプロバイダーの場合のエラー。
func TestLoadConfig_UnknownProvider(t *testing.T) {
	_, err := brain.LoadConfig(brain.ConfigHint{Provider: "unknown-provider"})
	if err == nil {
		t.Error("expected error for unknown provider, got nil")
	}
}

// LoadConfig: Ollama で hint に BaseURL が指定されている場合は環境変数より優先。
func TestLoadConfig_Ollama_HintBaseURLPriority(t *testing.T) {
	t.Setenv("OLLAMA_BASE_URL", "http://env-server:11434")
	t.Setenv("OLLAMA_MODEL", "env-model")

	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderOllama,
		BaseURL:  "http://hint-server:11434",
		Model:    "hint-model",
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// hint の値が優先される
	if cfg.BaseURL != "http://hint-server:11434" {
		t.Errorf("BaseURL: got %q, want http://hint-server:11434", cfg.BaseURL)
	}
	if cfg.Model != "hint-model" {
		t.Errorf("Model: got %q, want hint-model", cfg.Model)
	}
}

// LoadConfig: Ollama でモデルが環境変数から読まれること。
func TestLoadConfig_Ollama_ModelFromEnv(t *testing.T) {
	t.Setenv("OLLAMA_BASE_URL", "")
	t.Setenv("OLLAMA_MODEL", "codellama")

	cfg, err := brain.LoadConfig(brain.ConfigHint{Provider: brain.ProviderOllama})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Model != "codellama" {
		t.Errorf("Model: got %q, want codellama", cfg.Model)
	}
}

// =============================================================================
// brain.New エッジケース
// =============================================================================

// brain.New: OpenAI でトークンが空の場合のエラー。
func TestBrain_New_OpenAI_EmptyToken_ReturnsError(t *testing.T) {
	_, err := brain.New(brain.Config{
		Provider: brain.ProviderOpenAI,
		Model:    "gpt-4o",
		AuthType: brain.AuthAPIKey,
		Token:    "",
	})
	if err == nil {
		t.Error("expected error for empty OpenAI token, got nil")
	}
}

// brain.New: Ollama でトークンが空の場合でもダミートークンが設定されること。
func TestBrain_New_Ollama_EmptyToken_SetsDefault(t *testing.T) {
	action := `{"thought":"test","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		Token:    "", // 空 → ダミートークンが設定されるはず
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, empty token): %v", err)
	}
	if b == nil {
		t.Fatal("brain should not be nil")
	}
}

// brain.New: Ollama で BaseURL が空の場合にデフォルト URL が設定されること。
func TestBrain_New_Ollama_EmptyBaseURL_SetsDefault(t *testing.T) {
	// BaseURL が空の場合はデフォルト値(localhost:11434)が設定される
	// （実際の接続はしないが、オブジェクトが正常に作成されることを確認）
	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  "", // 空 → デフォルトが使われるはず
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, empty base URL): %v", err)
	}
	if b == nil {
		t.Fatal("brain should not be nil")
	}
	if b.Provider() != "ollama" {
		t.Errorf("Provider(): got %q, want %q", b.Provider(), "ollama")
	}
}

// brain.New: Ollama でトークンが空でなく指定されている場合はそのまま使用。
func TestBrain_New_Ollama_WithToken(t *testing.T) {
	action := `{"thought":"test","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		Token:    "custom-ollama-token",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama, with token): %v", err)
	}
	if b == nil {
		t.Fatal("brain should not be nil")
	}
}

// =============================================================================
// Anthropic レスポンスの content に混合ブロック（tool_use + text）がある場合
// =============================================================================

func TestAnthropicBrain_Think_MixedContentBlocks(t *testing.T) {
	// 最初のブロックが tool_use で、2番目が text の場合 → text が使われること
	mixedContentResp := `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "tool_use", "text": ""},
			{"type": "text", "text": "{\"thought\":\"found it\",\"action\":\"think\"}"}
		],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 20}
	}`
	srv := mockAnthropicServer(t, mixedContentResp)
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
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err != nil {
		t.Fatalf("Think: %v", err)
	}
	if result.Action != schema.ActionThink {
		t.Errorf("Action: got %q, want %q", result.Action, schema.ActionThink)
	}
	if result.Thought != "found it" {
		t.Errorf("Thought: got %q, want %q", result.Thought, "found it")
	}
}

// Anthropic ExtractTarget: content に混合ブロックがある場合。
func TestAnthropicBrain_ExtractTarget_MixedContentBlocks(t *testing.T) {
	mixedContentResp := `{
		"id": "msg_test",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "tool_use", "text": ""},
			{"type": "text", "text": "{\"host\":\"mixed.htb\",\"instruction\":\"test\"}"}
		],
		"model": "claude-sonnet-4-6",
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 10, "output_tokens": 20}
	}`
	srv := mockAnthropicServer(t, mixedContentResp)
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

	host, instruction, err := b.ExtractTarget(context.Background(), "mixed.htbを攻略して")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "mixed.htb" {
		t.Errorf("host: got %q, want %q", host, "mixed.htb")
	}
	if instruction != "test" {
		t.Errorf("instruction: got %q, want %q", instruction, "test")
	}
}

// =============================================================================
// OpenAI Think — BaseURL パスバリエーション
// =============================================================================

// OpenAI Think: BaseURL が /v1 で終わる場合（Ollama 互換）。
func TestOpenAIBrain_Think_BaseURLWithV1(t *testing.T) {
	action := `{"thought":"checking","action":"think"}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOpenAI,
		Model:    "gpt-4o",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-openai-test",
		BaseURL:  srv.URL + "/v1",
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

// OpenAI ExtractTarget: BaseURL が /v1 で終わる場合（Ollama 互換）。
func TestOpenAIBrain_ExtractTarget_BaseURLWithV1(t *testing.T) {
	extractJSON := `{"host":"v1test.htb","instruction":"test"}`
	srv := mockOpenAIServer(t, openAIResponse(extractJSON))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOpenAI,
		Model:    "gpt-4o",
		AuthType: brain.AuthAPIKey,
		Token:    "sk-openai-test",
		BaseURL:  srv.URL + "/v1",
	})
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	host, _, err := b.ExtractTarget(context.Background(), "v1test.htbを攻略して")
	if err != nil {
		t.Fatalf("ExtractTarget: %v", err)
	}
	if host != "v1test.htb" {
		t.Errorf("host: got %q, want %q", host, "v1test.htb")
	}
}

// =============================================================================
// DetectAvailableProviders 追加テスト
// =============================================================================

// DetectAvailableProviders: ANTHROPIC_AUTH_TOKEN のみ設定された場合。
func TestDetectAvailableProviders_AnthropicAuthToken(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-auth-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	providers := brain.DetectAvailableProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one provider when ANTHROPIC_AUTH_TOKEN is set")
	}
	if providers[0] != brain.ProviderAnthropic {
		t.Errorf("first provider: got %q, want anthropic", providers[0])
	}
}

// DetectAvailableProviders: 全プロバイダーが利用可能な場合。
func TestDetectAvailableProviders_All(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "sk-openai-test")
	t.Setenv("OLLAMA_BASE_URL", "http://localhost:11434")

	providers := brain.DetectAvailableProviders()
	if len(providers) != 3 {
		t.Fatalf("expected 3 providers, got %d: %v", len(providers), providers)
	}
	// 優先順位: Anthropic > OpenAI > Ollama
	if providers[0] != brain.ProviderAnthropic {
		t.Errorf("first provider: got %q, want anthropic", providers[0])
	}
	if providers[1] != brain.ProviderOpenAI {
		t.Errorf("second provider: got %q, want openai", providers[1])
	}
	if providers[2] != brain.ProviderOllama {
		t.Errorf("third provider: got %q, want ollama", providers[2])
	}
}

// =============================================================================
// Ollama ExtractTarget エッジケース
// =============================================================================

// Ollama ExtractTarget: API エラー。
func TestOllamaBrain_ExtractTarget_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama): %v", err)
	}

	_, _, err = b.ExtractTarget(context.Background(), "target.local をスキャン")
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}

// Ollama Think: API エラー。
func TestOllamaBrain_Think_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"model not found"}`))
	}))
	defer srv.Close()

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOllama,
		Model:    "llama3.2",
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("brain.New (ollama): %v", err)
	}

	_, err = b.Think(context.Background(), brain.Input{
		TargetSnapshot: `{"ip":"10.0.0.5"}`,
	})
	if err == nil {
		t.Error("expected error for API error response, got nil")
	}
}
