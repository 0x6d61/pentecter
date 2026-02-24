# Hybrid TUI Scroll Region (Deprecated)

## Status
This document is deprecated.
The scroll-region fixed-frame design is no longer the target architecture.

## Why Deprecated
The current UI direction is pi-style terminal output:
- native terminal scrollback
- no fixed bottom frame requirement
- no ANSI scroll-region ownership
- keyboard toggles for output/thinking folds (`Ctrl+O`, `Ctrl+T`)

## Canonical References
Use these documents instead:
- `docs/architecture_design/ui-spec.md`
- `docs/architecture_design/tui-interaction.md`
- `docs/architecture_design/display-rendering.md`

## Migration Note
If code still depends on scroll-region assumptions, treat that as technical debt.
New work must follow the canonical pi-style specifications.
