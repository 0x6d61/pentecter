# Getting Started

## Prerequisites

- **Go 1.21+** — for building from source
- **Docker** (optional) — for sandboxed tool execution and demo environment
- **LLM API Key** — at least one of: Anthropic, OpenAI, or Ollama

## Installation

### Build from Source

```bash
git clone https://github.com/0x6d61/pentecter.git
cd pentecter
go build -o pentecter ./cmd/pentecter
```

### Verify Installation

```bash
./pentecter --help
```

## Configuration

Set at least one LLM provider's API key:

```bash
# Option 1: Anthropic Claude (recommended)
export ANTHROPIC_API_KEY=sk-ant-xxx...

# Option 2: OpenAI
export OPENAI_API_KEY=sk-xxx...

# Option 3: Ollama (local, no API key needed)
export OLLAMA_BASE_URL=http://localhost:11434
```

You can also create a `.env` file in the working directory:

```env
ANTHROPIC_API_KEY=sk-ant-xxx...
```

## First Run

### Single Target

```bash
./pentecter 10.0.0.5
```

### Multiple Targets

```bash
./pentecter 10.0.0.5 10.0.0.8 10.0.0.12
```

### With Specific Provider

```bash
./pentecter -provider ollama -model llama3.2 10.0.0.5
```

### Auto-Approve Mode

Skip all proposal confirmations (use with caution):

```bash
./pentecter -auto-approve 10.0.0.5
```

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-provider` | string | (auto-detect) | LLM provider: `anthropic`, `openai`, or `ollama` |
| `-model` | string | (provider default) | Model name (e.g., `claude-sonnet-4-6`, `gpt-4o`, `llama3.2`) |
| `-auto-approve` | bool | `false` | Auto-approve all commands without proposals |

## What Happens Next

1. The TUI launches with a split-pane layout
2. Each target gets an AI agent that begins autonomous reconnaissance
3. The agent scans ports, enumerates services, and identifies vulnerabilities
4. When a high-risk action is needed, a **proposal** appears for your approval
5. You can chat with the agent, switch models, or add new targets at any time

See the [TUI Guide](TUI-Guide) for detailed interface instructions.
