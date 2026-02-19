# TUI Guide

## Interface Layout

```
┌──────────────────────────────────────────────────────────────────┐
│ PENTECTER  Focus: 10.0.0.5 [SCANNING]  [LIST] [LOG] [INPUT]     │
├─────────────────┬────────────────────────────────────────────────┤
│  TARGETS        │  ═══ Session: 10.0.0.5 [SCANNING] ═══         │
│                 │                                                │
│  ◎ 10.0.0.5    │  ─── Turn 1 ───                                │
│  ○ 10.0.0.8    │  15:04:06 [AI  ] Starting recon on 10.0.0.5    │
│  ○ 10.0.0.12   │  15:04:07 [TOOL] nmap -sV 10.0.0.5             │
│                 │  15:04:22 [TOOL] PORT 80 open http              │
│                 │    → exit 0 (12 lines)                         │
│                 │  ─── Turn 2 ───                                │
│                 │  15:04:23 [AI  ] Detected Apache 2.4.49        │
│                 │  15:04:24 [TOOL] curl http://10.0.0.5/          │
│                 │    → exit 0 (45 lines)                         │
├─────────────────┴────────────────────────────────────────────────┤
│  > scan for sql injection vulnerabilities                        │
└──────────────────────────────────────────────────────────────────┘
```

### Three Panes

| Pane | Location | Purpose |
|------|----------|---------|
| **TARGETS** | Left | List of all targets with status icons |
| **SESSION LOG** | Right | Real-time log for the selected target |
| **INPUT** | Bottom | Chat input, slash commands, target addition |

### Status Icons

| Icon | Status | Meaning |
|------|--------|---------|
| `○` | IDLE | Not yet started |
| `◎` | SCANNING | Reconnaissance in progress |
| `▶` | RUNNING | Active command execution |
| `⏸` | PAUSED | Awaiting proposal approval |
| `⚡` | PWNED | Successfully compromised |
| `✗` | FAILED | Assessment failed |

### Log Sources

| Label | Color | Source |
|-------|-------|--------|
| `[AI  ]` | Purple | AI agent decisions and analysis |
| `[TOOL]` | Cyan | Command execution and output |
| `[SYS ]` | Gray | System events (stall, errors) |
| `[USER]` | Green | Your chat messages |

### Turn Separators

Session logs are grouped by **turns**. Each turn represents one Brain decision cycle:

```
─── Turn 3 ───
15:04:06 [AI  ] Detected Apache 2.4.49
15:04:07 [TOOL] nmap -sV 10.0.0.5
15:04:22 [TOOL] PORT 80 open http
  → exit 0 (12 lines)            ← Success (green)
─── Turn 4 ───
15:04:23 [AI  ] Trying exploit...
15:04:24 [TOOL] python3 -c "..."
15:04:25 [TOOL] SyntaxError: invalid
  → exit 2: SyntaxError: invalid  ← Failure (red)
```

## Keyboard Shortcuts

### Global

| Key | Action |
|-----|--------|
| `Tab` | Cycle focus: LIST → LOG → INPUT → LIST |
| `Ctrl+C` | Quit application |

### Proposal Response (when proposal is displayed)

| Key | Action |
|-----|--------|
| `y` | Approve and execute the proposed command |
| `n` | Reject the proposal |
| `e` | Edit the command (copies to input bar) |

### Target List (left pane focused)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Select previous/next target |

### Session Log (right pane focused)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Scroll up/down |
| `Page Up` / `Page Down` | Scroll by page |

### Input Bar (bottom pane focused)

| Key | Action |
|-----|--------|
| `Enter` | Submit command or message |
| `→` (Right Arrow) | Accept autocomplete suggestion |

### Select Mode (after `/model` or `/approve`)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move selection |
| `Enter` | Confirm selection |
| `Esc` | Cancel and return to normal input |

## Slash Commands

### `/model` — Switch LLM Provider/Model

Opens a 2-step interactive selection:

1. **Select provider**: `anthropic`, `openai`, or `ollama`
2. **Select model**: Provider-specific model list

Only providers with configured API keys are shown.

### `/approve` — Toggle Auto-Approve

Opens an interactive selection:
- **ON** — All commands execute without confirmation
- **OFF** — High-risk commands require `[y/n]` approval

### `/target <host>` — Add Target

```
/target example.com
/target 192.168.1.1
```

Adds a new target and starts its AI agent immediately.

### Bare IP Address

Simply typing an IP address (e.g., `10.0.0.5`) adds it as a target.

### Natural Language + IP

When no targets exist, you can combine an IP with instructions:

```
192.168.81.1 scan for web vulnerabilities
```

This adds `192.168.81.1` as a target and sends "scan for web vulnerabilities" to the AI agent.

### Skill Invocation

Type `/skill-name` to invoke a predefined skill template:

```
/web-recon
/full-scan
/sqli-check
```

See [Skills](Skills) for details.

### Chat Messages

Any other text is sent as a message to the active target's AI agent:

```
focus on port 445
try a different approach
what vulnerabilities have you found?
```

The AI agent prioritizes user messages over its autonomous assessment.

## Proposal Workflow

When the AI identifies a high-risk action:

```
⚠  PROPOSAL — Awaiting approval
  Exploit Apache 2.4.49 Path Traversal (CVE-2021-41773)
  Tool: metasploit exploit/multi/http/apache_normalize_path_rce --target 10.0.0.8
  [y] Approve  [n] Reject  [e] Edit
```

1. Press `y` to approve and execute
2. Press `n` to reject (AI will try alternative approach)
3. Press `e` to edit the command before executing
