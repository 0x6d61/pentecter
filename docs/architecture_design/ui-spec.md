# Pentecter UI Spec (pi-style Terminal)

## Scope
This document is the canonical UI specification for Pentecter.
It replaces old full-screen TUI assumptions and defines the behavior used for implementation.

## Goals
- Use terminal native scrollback as the primary log history.
- Keep interaction keyboard-first and low-latency.
- Keep output safe under concurrent goroutines.
- Keep commands discoverable with slash-command UX.

## Non-goals
- Full-screen ownership of terminal buffers.
- Dedicated copy mode in the UI.
- Runtime toggle of approval policy via slash command.

## High-level Layout
- Output is append-only text blocks in normal terminal flow.
- Prompt is shown at the current cursor line.
- Status is shown as lightweight line output (not a fixed pane requirement).
- No scroll-region pinning, no viewport virtualization.

## Input Model
- `Enter`: submit current input.
- `Shift+Enter`: insert newline in multi-line input.
- `Ctrl+Enter`: insert newline on terminals where Shift+Enter is unavailable (notably Windows Terminal).
- `Ctrl+J`: fallback newline key when terminal key mapping is limited.
- `Ctrl+C`: quit confirmation.

## Slash Commands
| Command | Purpose |
|---|---|
| `/model` | Select or switch provider/model |
| `/targets` | Show target list and switch active target |
| `/target <host>` | Add a target |
| `/recontree` | Show reconnaissance tree |
| `/skip-recon` | Unlock recon phase manually |
| `/status` | Print current runtime status |
| `/fold` | Toggle tool-output folding (alias of `Ctrl+O`) |

Removed from UI command surface:
- `/copy`
- `/approve`

## Key Bindings
| Key | Behavior |
|---|---|
| `Ctrl+O` | Collapse/expand tool output blocks globally |
| `Ctrl+T` | Collapse/expand thinking blocks globally |
| `Ctrl+C` | Enter quit confirmation |

## Input Modes
| Mode | Prompt | Trigger |
|---|---|---|
| `Normal` | `> ` | Default |
| `Select` | `select [1-N/q] > ` | `/model` or `/targets` without explicit argument |
| `ConfirmQuit` | `Quit Pentecter? [y/n] > ` | `Ctrl+C` |
| `Proposal` (optional) | `approve? [y/n/e] > ` | Only when approval gate is enabled at startup |

## Folding Semantics
- Tool output folding and thinking folding are independent global states.
- `Ctrl+O` affects only command/tool output blocks.
- `Ctrl+T` affects only thinking blocks.
- Fold indicators must show hidden line counts.

## Approval Policy
- Approval behavior is configured at startup (CLI/config), not via runtime slash command.
- UI can still display proposal prompt if startup policy requires approval.

## Compatibility Notes
- Existing operator flow remains command-first.
- `Ctrl+O` and `Ctrl+T` are aligned with pi-style behavior.
- Multi-line input behavior follows pi conventions with a Windows-friendly fallback.
