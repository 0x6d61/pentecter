# Pentecter

**Pentecter** is an autonomous penetration testing agent with a TUI (Terminal User Interface). It combines LLM-powered decision-making with human approval gates for high-risk actions.

## Key Features

- **Autonomous Reconnaissance** — AI-driven port scanning, service enumeration, and vulnerability detection
- **Human-in-the-Loop Exploitation** — Proposals for high-risk actions require explicit user approval
- **Multi-Provider LLM Support** — Anthropic Claude, OpenAI GPT, and Ollama (local models)
- **Skills System** — Reusable penetration testing templates (`/web-recon`, `/full-scan`, `/sqli-check`)
- **Docker Sandbox** — Tool execution in isolated containers when available
- **Knowledge Base** — Built-in HackTricks search for attack techniques and exploit methodologies
- **Persistent Memory** — Findings are stored per-host and carried across sessions
- **Lateral Movement** — AI can discover and add new targets during assessment

## Quick Start

```bash
export ANTHROPIC_API_KEY=sk-ant-xxx...
go build -o pentecter ./cmd/pentecter
./pentecter 10.0.0.5
```

## Wiki Pages

| Page | Description |
|------|-------------|
| [Getting Started](Getting-Started) | Installation, build, and first run |
| [Configuration](Configuration) | Environment variables, tool definitions, blacklist |
| [TUI Guide](TUI-Guide) | Interface layout, keyboard shortcuts, slash commands |
| [Skills](Skills) | Skill templates and how to create custom skills |
| [Agent Behavior](Agent-Behavior) | How the AI agent works, proposal workflow, stall detection |
| [Docker & Demo](Docker-and-Demo) | Demo environment setup with Metasploitable2 |
| [Architecture](Architecture) | High-level system architecture and design decisions |

## Autonomy Level: 2.5

| Category | Behavior |
|----------|----------|
| Reconnaissance (nmap, curl, nikto) | Automatic |
| Exploitation (metasploit, sqlmap) | Proposed (requires approval) |
| Direct host access | Blocked (proposal + approval) |
| Docker-sandboxed tools | Auto-execute |

## License

This project is intended for **authorized security testing only**. Always obtain written permission before testing any system.
