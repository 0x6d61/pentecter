# Skills

Skills are reusable penetration testing templates that guide the AI agent through structured assessment workflows. They are invoked with slash commands in the TUI input bar.

## Available Skills

### `/web-recon` — Web Application Reconnaissance

Performs initial web application reconnaissance:

1. Port scan for common web ports (80, 443, 8080, 8443)
2. Nikto vulnerability scan
3. WordPress detection and enumeration
4. Admin panel discovery
5. Records findings to memory

### `/full-scan` — Full Port Scan + Service Enumeration

Comprehensive network assessment:

1. Full TCP port discovery (`nmap -p-`)
2. Service version detection on open ports
3. OS fingerprinting
4. Default credential checks on discovered services
5. Records all findings

### `/sqli-check` — SQL Injection Assessment

SQL injection vulnerability detection:

1. Error-based SQLi testing
2. Boolean-based blind SQLi testing
3. Time-based blind SQLi testing
4. Proposes sqlmap for full exploitation (requires approval)
5. Records discovered injection points

## Using Skills

Type the skill name with a `/` prefix in the input bar:

```
> /web-recon
```

The skill's full prompt is expanded and sent to the AI agent as a user instruction. The AI then follows the methodology step-by-step, using appropriate tools and recording findings.

## Creating Custom Skills

Skills are stored in the `skills/` directory. Two formats are supported:

### Markdown Format (Recommended)

Create `skills/my-skill.md`:

```markdown
---
name: my-skill
description: Short description of what this skill does
---

## Objective
Describe the assessment objective.

## Steps
1. First, run a port scan with nmap
2. Check for specific vulnerabilities
3. Attempt exploitation if vulnerabilities found
4. Record all findings using the memory action

## Tools to Use
- nmap for port scanning
- curl for HTTP requests
- nikto for web vulnerability scanning

## Notes
- Use "propose" for any exploitation attempts
- Record all findings with "memory" action
```

### YAML Format

Create `skills/my-skill.yaml`:

```yaml
name: my-skill
description: Short description
prompt: |
  Full prompt text for the AI agent.
  Describe the assessment methodology in detail.
```

### Skill File Requirements

- **name**: Must be non-empty (used as the slash command)
- **description**: Brief description shown in help
- **prompt/body**: The full instruction text for the AI agent

### How Skills are Expanded

When a user types `/my-skill`:

1. The skills registry looks up `my-skill` by name
2. The full prompt text is retrieved
3. The prompt is injected into the Brain context as a user message
4. The AI agent follows the instructions autonomously

If arguments are provided (e.g., `/my-skill target.com`), they are appended to the prompt.
