# Architecture

## System Overview

```
┌─────────────────────────────────────────────────┐
│                     TUI                          │
│  (Bubble Tea)                                    │
│  ┌──────────┐  ┌───────────┐  ┌──────────────┐ │
│  │  Target   │  │  Session  │  │    Input     │ │
│  │  List     │  │  Log      │  │    Bar       │ │
│  └──────────┘  └───────────┘  └──────────────┘ │
│       │              ▲              │            │
│       │         Events│         UserMsg          │
└───────┼──────────────┼──────────────┼────────────┘
        │              │              │
   ┌────▼──────────────┼──────────────▼────────┐
   │              Agent Team                    │
   │                                            │
   │  ┌─────────┐  ┌─────────┐  ┌─────────┐  │
   │  │ Loop #1 │  │ Loop #2 │  │ Loop #3 │  │
   │  │10.0.0.5 │  │10.0.0.8 │  │10.0.0.12│  │
   │  └────┬────┘  └────┬────┘  └────┬────┘  │
   │       │             │             │       │
   └───────┼─────────────┼─────────────┼───────┘
           │             │             │
   ┌───────▼─────────────▼─────────────▼───────┐
   │                  Brain                     │
   │  (LLM: Anthropic / OpenAI / Ollama)       │
   │  Input → JSON Action → Loop executes      │
   └───────────────────┬───────────────────────┘
                       │
   ┌───────────────────▼───────────────────────┐
   │              CommandRunner                 │
   │  ┌──────────┐  ┌──────────┐  ┌────────┐ │
   │  │ Registry │  │Blacklist │  │LogStore│ │
   │  │(tools/*) │  │(safety)  │  │(history)│ │
   │  └──────────┘  └──────────┘  └────────┘ │
   │                     │                     │
   │         ┌───────────┼───────────┐        │
   │         ▼           ▼           ▼        │
   │      Docker      Direct      Proposal    │
   │      Exec        Exec        (TUI)       │
   └───────────────────────────────────────────┘
```

## Core Components

### Brain (`internal/brain/`)

The LLM abstraction layer. Supports three providers through a unified `Brain` interface:

- **Anthropic** — Claude models (recommended)
- **OpenAI** — GPT models
- **Ollama** — Local models via OpenAI-compatible API

**Key responsibilities:**
- Build system prompt (pentest-specific instructions)
- Build user prompt (target snapshot + tool output + command history + user message + turn count)
- Parse JSON action responses from LLM
- Handle provider-specific API differences

### Agent (`internal/agent/`)

**Target** — Data model for a pentest target (host, status, logs, entities, proposal)

**Loop** — Orchestrator connecting Brain, CommandRunner, and TUI:
- Runs Brain.Think() → executes action → evaluates result
- Manages failure detection (3 signals)
- Handles user message draining (3 drain points)
- Tracks turn count and command history

**Team** — Manages multiple concurrent Loops (one per target):
- Dynamic target addition
- Shared Brain instance (switchable at runtime)
- Shared CommandRunner

**Event** — Message types from Agent to TUI:
- `EventLog` — Regular log line
- `EventProposal` — Action requiring approval
- `EventComplete` — Assessment finished
- `EventError` — Unrecoverable error
- `EventStalled` — Consecutive failures, awaiting user direction
- `EventAddTarget` — Lateral movement
- `EventTurnStart` — New decision cycle
- `EventCommandResult` — Command execution summary

### TUI (`internal/tui/`)

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) framework.

**Key design constraints:**
- No blocking operations in the main goroutine
- All heavy work happens in Agent goroutines
- Communication via buffered channels (32-event buffer)
- Event-driven updates (AgentEventMsg)

### Tools (`internal/tools/`)

**Registry** — Tool definitions loaded from `tools/*.yaml`

**CommandRunner** — Executes commands with:
- Docker sandboxing (when available)
- Blacklist checking (safety gate)
- Auto-approve or proposal routing
- Output streaming (line-by-line to TUI)
- Output truncation (head-tail strategy)
- Entity extraction from tool output

**LogStore** — Persistent execution history

### Memory (`internal/memory/`)

Persistent knowledge graph stored as Markdown files:
- One file per host (`memory/<host>.md`)
- Stores vulnerabilities, credentials, artifacts, notes
- Loaded into Brain context for each assessment
- Supports cross-session continuity

### Skills (`internal/skills/`)

Template-based assessment methodologies:
- Loaded from `skills/` directory (`.md` or `.yaml`)
- Expanded on `/skill-name` invocation
- Injected into Brain context as user instructions

## Data Flow

### Normal Command Execution

```
User types: "scan for web vulnerabilities"
  → TUI sends to userMsg channel
  → Loop.drainUserMsg() picks up message
  → Loop calls Brain.Think(context + userMessage)
  → Brain returns: {"action": "run", "command": "nmap -sV -p 80,443 10.0.0.5"}
  → Loop calls CommandRunner.Run("nmap -sV -p 80,443 10.0.0.5")
  → CommandRunner checks: Docker available? → Yes → Execute in container
  → Output streamed line-by-line → TUI displays via EventLog
  → Result evaluated: exit 0, no failure patterns → success
  → Next iteration: Brain sees output in context
```

### Proposal Flow

```
Brain returns: {"action": "propose", "command": "msfconsole -r exploit.rc"}
  → Loop creates Proposal object
  → Target.SetProposal() → status = PAUSED
  → EventProposal sent to TUI
  → TUI renders proposal box with [y/n/e]
  → User presses 'y'
  → TUI sends true to approve channel
  → Loop receives approval
  → CommandRunner.ForceRun("msfconsole -r exploit.rc")
  → Result streamed and evaluated
```

### Stall Recovery

```
Command 1: exit 1 → failure count: 1
Command 2: exit 2 → failure count: 2
Command 3: pattern match "SyntaxError" → failure count: 3
  → Threshold reached (3)
  → EventStalled sent to TUI
  → Status = PAUSED
  → Loop.waitForUserMsg() blocks
  → User types: "try a different tool"
  → Failure count reset to 0
  → Loop resumes with user's message in Brain context
```

## Design Principles

1. **Brain never touches the OS directly** — All execution goes through CommandRunner
2. **TUI goroutine never blocks** — Heavy work in Agent goroutines, communication via channels
3. **Target is the single source of truth** — All state (logs, status, proposal, entities) managed by Target
4. **Safety by default** — Blacklist blocks dangerous commands, proposals require approval
5. **Autonomous but controllable** — AI runs independently but human can intervene at any time
