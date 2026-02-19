# Configuration

## Environment Variables

### LLM Providers

| Variable | Provider | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic | Claude API key (`sk-ant-...`) |
| `CLAUDE_CODE_OAUTH_TOKEN` | Anthropic | OAuth token from `claude auth token` (`sk-ant-ocp01-...`) |
| `ANTHROPIC_AUTH_TOKEN` | Anthropic | Alternative OAuth token variable |
| `OPENAI_API_KEY` | OpenAI | OpenAI API key (`sk-...`) |
| `OLLAMA_BASE_URL` | Ollama | Server URL (default: `http://localhost:11434`) |
| `OLLAMA_MODEL` | Ollama | Model name (default: `llama3.2`) |

### Provider Auto-Detection

When no `-provider` flag is given, Pentecter checks environment variables in this order:

1. **Anthropic** — `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, or `ANTHROPIC_AUTH_TOKEN`
2. **OpenAI** — `OPENAI_API_KEY`
3. **Ollama** — `OLLAMA_BASE_URL` (must be explicitly set)

The first detected provider is used.

### .env File

Pentecter automatically loads a `.env` file from the working directory using [godotenv](https://github.com/joho/godotenv):

```env
ANTHROPIC_API_KEY=sk-ant-xxx...
```

## Config Files Overview

| File | Purpose |
|------|---------|
| `.env` | Environment variables (auto-loaded) |
| `config/blacklist.yaml` | Dangerous command patterns |
| `config/mcp.yaml` | MCP server definitions |
| `config/knowledge.yaml` | Knowledge base paths (HackTricks) |
| `tools/*.yaml` | Tool execution configurations |
| `skills/*.md` | Skill templates |
| `memory/` | Persistent findings storage (auto-created) |

## Tool Definitions

Tool configurations are stored in `tools/*.yaml`. Each file defines how a tool is executed.

### Example: nmap.yaml

```yaml
name: nmap
description: Port scanning and service detection
tags: [recon, port-scan]
timeout: 600
docker:
  image: instrumentisto/nmap
  network: host
  fallback: true
output:
  strategy: head_tail
  head_lines: 50
  tail_lines: 30
```

### Tool Configuration Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Tool binary name |
| `description` | string | Human-readable description |
| `tags` | []string | Categorization tags |
| `timeout` | int | Max execution time in seconds |
| `proposal_required` | bool | Whether user approval is always required |
| `docker.image` | string | Docker image to use |
| `docker.network` | string | Docker network mode (`host` or `bridge`) |
| `docker.fallback` | bool | Fall back to host execution if Docker unavailable |
| `output.strategy` | string | Truncation strategy: `head_tail` or `http_response` |
| `output.head_lines` | int | Lines to keep from output start |
| `output.tail_lines` | int | Lines to keep from output end |

### Registered Tools

| Tool | Docker Image | Approval | Purpose |
|------|-------------|----------|---------|
| `nmap` | instrumentisto/nmap | No (Docker) | Port scanning |
| `nikto` | securecodebox/nikto | No (Docker) | Web vulnerability scanning |
| `curl` | — | No | HTTP requests |
| `bash` | — | No | Shell scripts |
| `python3` | — | No | Python scripts |
| `hydra` | Docker available | No (Docker) | Credential testing |
| `msfconsole` | — | Yes | Metasploit framework |
| `nc` | — | No | Netcat connections |
| `socat` | — | No | Data relay |

## Blacklist

The blacklist prevents dangerous commands from being executed, regardless of approval.

### Default Blacklist

If no `config/blacklist.yaml` exists, these patterns are blocked:

- `rm -rf /` — Recursive deletion
- `dd if=` — Disk operations
- `mkfs` — Filesystem formatting
- `shutdown` / `reboot` — System halt
- Forkbomb patterns

### Custom Blacklist

Create `config/blacklist.yaml`:

```yaml
patterns:
  - 'rm\s+-rf\s+/'
  - 'dd\s+if='
  - '\bshutdown\b'
  - '\breboot\b'
  - ':\(\)\{.*\|.*\}'
```

Patterns are regular expressions matched against the full command string.

## MCP Server Configuration

Pentecter can extend its capabilities by connecting to [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) servers. Each server is started as a subprocess using **stdio transport** and provides additional tools that the Brain can invoke.

### Config File

`config/mcp.yaml`

### Server Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Server identifier (referenced by Brain) |
| `command` | string | Executable to start the server |
| `args` | []string | Command line arguments |
| `env` | map | Environment variables passed to the subprocess |
| `proposal_required` | bool | Whether user approval is needed before calling this server's tools (default: `false`) |

### Variable Expansion

The `command`, `args`, and `env` values support `${VAR}` expansion from the host environment. For example, `${HOME}` expands to the current user's home directory.

### Example: HackTricks MCP Server

```yaml
servers:
  - name: hacktricks
    command: node
    args: ["${HOME}/hacktricks-mcp-server/dist/index.js"]
    env: {}
    proposal_required: false
```

**Setup:**

```bash
git clone https://github.com/Xplo8E/hacktricks-mcp-server.git ~/hacktricks-mcp-server
cd ~/hacktricks-mcp-server && npm install && npm run build
```

### How It Works

When Pentecter starts, it reads `config/mcp.yaml` and launches each defined server as a child process. The Brain communicates with these servers over stdio, discovering and invoking the tools they expose. If `proposal_required` is `true`, the Brain will present a proposal to the user before calling any tool on that server.

## Knowledge Base Configuration

Pentecter includes a built-in knowledge base system that gives the Brain direct access to local documentation repositories (e.g., HackTricks). Unlike MCP servers, this requires **no Node.js or external dependencies** — it works by reading files directly from disk.

### Config File

`config/knowledge.yaml`

### Knowledge Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Identifier for the knowledge base |
| `path` | string | Path to the content directory (`${VAR}` expanded from host env) |

### Variable Expansion

The `path` field supports `${VAR}` expansion from the host environment. For example, `${HOME}` expands to the current user's home directory.

### Example

```yaml
knowledge:
  - name: hacktricks
    path: "${HOME}/hacktricks/src"
```

### Setup

Clone the HackTricks repository (shallow clone to save space):

```bash
git clone --depth 1 https://github.com/carlospolop/hacktricks.git ~/hacktricks
```

### How It Works

When a knowledge base is configured, the Brain gains two additional actions:

- **`search_knowledge`** — Searches across the knowledge base files for relevant techniques, exploits, or methodologies.
- **`read_knowledge`** — Reads a specific knowledge base file to get detailed information.

The Brain automatically uses these actions during reconnaissance and exploitation planning to find relevant attack techniques. No Node.js runtime or MCP server is required — the knowledge base is accessed through direct filesystem reads.

## SubAgent Configuration

When the Brain delegates tasks to SmartSubAgents (for parallel execution), the sub-agents can optionally use a different LLM model or provider than the main Brain.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SUBAGENT_MODEL` | LLM model for SmartSubAgent tasks | Same as main Brain |
| `SUBAGENT_PROVIDER` | LLM provider for SmartSubAgent tasks | Same as main Brain |

### Example: Use a Lighter Model for Sub-Agents

```env
# Main Brain uses Claude Opus
ANTHROPIC_API_KEY=sk-ant-...

# Sub-agents use a faster/cheaper model
SUBAGENT_MODEL=claude-sonnet-4-20250514
```

### Example: Use a Different Provider for Sub-Agents

```env
# Main Brain uses Anthropic directly
ANTHROPIC_API_KEY=sk-ant-...

# Sub-agents use OpenRouter to distribute load
SUBAGENT_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-...
```

This is useful for:
- **Cost optimization** — Use a cheaper model for routine sub-tasks
- **Rate limit distribution** — Spread requests across multiple providers
- **Speed** — Use a faster model for sub-agents while keeping a stronger model for the main Brain

## Models

### Default Models per Provider

| Provider | Default Model | Alternatives |
|----------|--------------|--------------|
| Anthropic | `claude-sonnet-4-6` | `claude-opus-4-6`, `claude-haiku-4-5-20251001` |
| OpenAI | `gpt-4o` | `gpt-4o-mini`, `o3-mini` |
| Ollama | `llama3.2` | `llama3.2:3b`, `qwen2.5:7b`, `gemma2:9b` |

You can switch models at runtime using the `/model` command in the TUI.
