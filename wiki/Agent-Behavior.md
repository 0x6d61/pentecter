# Agent Behavior

## Agent Loop

Each target gets its own AI agent running in a dedicated goroutine. The agent follows this loop:

```
1. Check for pending user messages
2. Check if stalled (3+ consecutive failures) → pause, ask user
3. Emit turn start event
4. Call Brain.Think(context) → get action JSON
5. Post-think: drain any user messages received during thinking
6. Execute action (run, propose, memory, think, complete, add_target)
7. Post-exec: drain any user messages received during execution
8. Evaluate result (success/failure detection)
9. Loop back to step 1
```

## Action Types

The AI agent (Brain) returns one of these actions each turn:

| Action | Execution | Approval | Use Case |
|--------|-----------|----------|----------|
| `run` | Auto-execute | Based on tool config | Reconnaissance tools (nmap, curl, nikto) |
| `propose` | Paused | Always required | Exploitation, direct host access |
| `think` | None | — | Analyzing results, answering user questions |
| `memory` | Records finding | — | Storing vulnerabilities, credentials, artifacts |
| `complete` | Ends loop | — | Assessment finished |
| `add_target` | Adds new target | — | Lateral movement to discovered hosts |

## Failure Detection

The agent evaluates each command result using three signals:

### Signal A: Exit Code

Any non-zero exit code counts as a failure.

### Signal B: Output Pattern Matching

The following patterns in command output indicate failure:

**Network Errors:**
- `0 hosts up`, `Host seems down`, `host is down`
- `No route to host`, `Connection refused`, `Connection timed out`
- `Network is unreachable`, `Name or service not known`

**Program Errors:**
- `SyntaxError`, `command not found`, `No such file or directory`
- `Permission denied`, `Traceback (most recent call last)`
- `ModuleNotFoundError`, `ImportError`, `NameError`
- `panic:`, `Segmentation fault`

### Signal C: Command Repetition

If the same binary is used 3+ times in the last 5 commands, the agent detects it as stuck in a loop.

Example: `python3 a.py` → `python3 b.py` → `python3 c.py` → repetition detected.

## Stall Detection and Recovery

When **3 consecutive failures** occur:

1. Agent emits `EventStalled` with failure count
2. Target status changes to **PAUSED**
3. TUI displays warning: "Stalled after N consecutive failures. Waiting for direction."
4. Agent **blocks** waiting for user input
5. User types a message (e.g., "try a different approach")
6. Failure counter resets to 0
7. Agent resumes with user's guidance

## User Message Handling

User messages are checked at three points in the loop:

| Timing | Mechanism | Purpose |
|--------|-----------|---------|
| Loop start | `drainUserMsg()` or `pendingUserMsg` | Primary check |
| After Brain.Think() | `drainUserMsg()` → save to `pendingUserMsg` | Catch messages during AI thinking |
| After command execution | `drainUserMsg()` → save to `pendingUserMsg` | Catch messages during tool execution |

Messages saved to `pendingUserMsg` are delivered to the Brain on the **next turn**, ensuring no user input is lost.

The Brain always prioritizes user messages:
- User questions are answered with `think` action before other actions
- New directions from the user immediately change the agent's approach
- The system prompt explicitly instructs: "When a user message is present, you MUST respond to it"

## Turn Counter

Each loop iteration increments a turn counter. This is passed to the Brain as `TurnCount`:

- **Turns 1-10**: Normal autonomous operation
- **Turns 11+**: Brain receives a warning to consider proposing actions for human review

This prevents runaway autonomous execution on long assessments.

## Memory System

The agent can store findings using the `memory` action:

### Memory Types

| Type | Purpose | Example |
|------|---------|---------|
| `vulnerability` | Security issue found | CVE-2021-41773, SQL injection |
| `credential` | Username/password | FTP admin credentials |
| `artifact` | Extracted file/data | `/etc/passwd` contents |
| `note` | General information | Network topology notes |

### Persistence

Findings are stored in `memory/<host>.md` as Markdown files:

```markdown
# Pentecter Memory: 10.0.0.5

## [CRITICAL] CVE-2021-41773 Apache Path Traversal
- **Time**: 15:30:21
- **Description**: Apache 2.4.49 vulnerable to path traversal

## Credential: FTP Admin
- **Time**: 15:31:05
- **Details**: user:password found in vsftpd banner
```

Memory is automatically loaded into the Brain context for each target, enabling the agent to build on previous findings.

## Lateral Movement

When the agent discovers a new host during assessment:

1. Brain returns `add_target` action with the new host IP
2. A new target is added to the TUI target list
3. A new agent loop starts for the new target
4. Both agents run in parallel

## Command History

The agent maintains a history of the last 10 commands:
- Command string
- Exit code
- Output summary (first 200 characters)
- Timestamp

This history is included in the Brain context to help the AI avoid repeating failed approaches.
