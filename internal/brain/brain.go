package brain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// Provider identifies the LLM backend.
type Provider string

const (
	ProviderAnthropic  Provider = "anthropic"
	ProviderOpenAI     Provider = "openai"
	ProviderOpenRouter Provider = "openrouter"
	ProviderOllama     Provider = "ollama"
)

const defaultOpenRouterBaseURL = "https://openrouter.ai/api/v1"

// AuthType identifies the auth mechanism.
type AuthType string

const (
	AuthAPIKey     AuthType = "api_key"
	AuthOAuthToken AuthType = "oauth_token"
	AuthNone       AuthType = "none"
)

// MCPToolInfo is embedded into system prompts without importing internal/mcp.
type MCPToolInfo struct {
	Server      string
	Name        string
	Description string
	InputSchema map[string]any
}

// Config holds Brain configuration.
type Config struct {
	Provider  Provider
	Model     string
	AuthType  AuthType
	Token     string
	BaseURL   string
	ToolNames []string
	MCPTools  []MCPToolInfo

	// IsSubAgent switches prompts to sub-agent mode.
	IsSubAgent bool
	// IsReconAgent switches prompts to recon-agent mode.
	IsReconAgent bool
	// IsEventDrivenMain switches prompts to event-driven main-agent mode.
	IsEventDrivenMain bool
}

// Input is the reasoning context for Think.
type Input struct {
	TargetSnapshot  string
	ToolOutput      string
	LastCommand     string
	LastExitCode    int
	CommandHistory  string
	UserMessage     string
	TurnCount       int
	Memory          string
	ReconQueue      string
	TaskInstruction string
}

// Brain is the LLM interaction interface.
type Brain interface {
	Think(ctx context.Context, input Input) (*schema.Action, error)
	ExtractTarget(ctx context.Context, userText string) (host string, instruction string, err error)
	Provider() string
}

// New returns a concrete Brain implementation from config.
func New(cfg Config) (Brain, error) {
	switch cfg.Provider {
	case ProviderAnthropic:
		if cfg.Token == "" {
			return nil, errors.New("brain: Anthropic token is required")
		}
		return newAnthropicBrain(cfg)

	case ProviderOpenAI:
		if cfg.Token == "" {
			return nil, errors.New("brain: OpenAI API key is required")
		}
		return newOpenAIBrain(cfg)

	case ProviderOpenRouter:
		if cfg.Token == "" {
			return nil, errors.New("brain: OpenRouter API key is required")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = defaultOpenRouterBaseURL
		}
		cfg.BaseURL = ensureV1Path(cfg.BaseURL)
		return newOpenRouterBrain(cfg)

	case ProviderOllama:
		if cfg.Token == "" {
			cfg.Token = "ollama"
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:11434"
		}
		cfg.BaseURL = ensureV1Path(cfg.BaseURL)
		return newOllamaBrain(cfg)

	default:
		return nil, fmt.Errorf(
			"brain: unknown provider %q (supported: anthropic, openai, openrouter, ollama)",
			cfg.Provider,
		)
	}
}

func ensureV1Path(baseURL string) string {
	if len(baseURL) > 3 && baseURL[len(baseURL)-3:] == "/v1" {
		return baseURL
	}
	for len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL + "/v1"
}

// DetectAvailableProviders returns available providers by env vars.
func DetectAvailableProviders() []Provider {
	var providers []Provider

	if os.Getenv("ANTHROPIC_API_KEY") != "" ||
		os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" ||
		os.Getenv("ANTHROPIC_OAUTH_TOKEN") != "" ||
		os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" {
		providers = append(providers, ProviderAnthropic)
	}

	if os.Getenv("OPENAI_API_KEY") != "" {
		providers = append(providers, ProviderOpenAI)
	}

	if os.Getenv("OPENROUTER_API_KEY") != "" {
		providers = append(providers, ProviderOpenRouter)
	}

	if os.Getenv("OLLAMA_BASE_URL") != "" {
		providers = append(providers, ProviderOllama)
	}

	return providers
}

// ConfigHint holds override hints for LoadConfig.
type ConfigHint struct {
	Provider Provider
	Model    string
	BaseURL  string
}

// LoadConfig resolves auth + defaults from env.
func LoadConfig(hint ConfigHint) (Config, error) {
	cfg := Config{
		Provider: hint.Provider,
		Model:    hint.Model,
		BaseURL:  hint.BaseURL,
	}

	switch hint.Provider {
	case ProviderAnthropic:
		if cfg.Model == "" {
			cfg.Model = "claude-sonnet-4-6"
		}
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		for _, envKey := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"} {
			if token := os.Getenv(envKey); token != "" {
				cfg.Token = token
				cfg.AuthType = AuthOAuthToken
				return cfg, nil
			}
		}
		return cfg, errors.New(
			"brain: Anthropic credentials not found, set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (or ANTHROPIC_OAUTH_TOKEN)",
		)

	case ProviderOpenAI:
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		return cfg, errors.New("brain: OpenAI credentials not found, set OPENAI_API_KEY")

	case ProviderOpenRouter:
		if cfg.BaseURL == "" {
			cfg.BaseURL = os.Getenv("OPENROUTER_BASE_URL")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = defaultOpenRouterBaseURL
		}
		cfg.BaseURL = ensureV1Path(cfg.BaseURL)

		if cfg.Model == "" {
			cfg.Model = os.Getenv("OPENROUTER_MODEL")
		}
		cfg.Model = strings.TrimSpace(cfg.Model)
		if len(cfg.Model) > len("openrouter/") && strings.HasPrefix(strings.ToLower(cfg.Model), "openrouter/") {
			cfg.Model = strings.TrimSpace(cfg.Model[len("openrouter/"):])
		}
		if cfg.Model == "" {
			cfg.Model = "openai/gpt-4o-mini"
		}

		if key := os.Getenv("OPENROUTER_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		return cfg, errors.New("brain: OpenRouter credentials not found, set OPENROUTER_API_KEY")

	case ProviderOllama:
		if cfg.BaseURL == "" {
			cfg.BaseURL = os.Getenv("OLLAMA_BASE_URL")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:11434"
		}
		if cfg.Model == "" {
			cfg.Model = os.Getenv("OLLAMA_MODEL")
		}
		if cfg.Model == "" {
			cfg.Model = "llama3.2"
		}
		cfg.Token = "ollama"
		cfg.AuthType = AuthNone
		return cfg, nil

	default:
		return cfg, fmt.Errorf("brain: unknown provider %q", hint.Provider)
	}
}
