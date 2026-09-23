# frisk

Claude Code PreToolUse gate for Bash. Design: [DESIGN.md](DESIGN.md).

## Core rules

- **KISS** - the simplest thing that works. One file, stdlib only, no new abstractions.
- **YAGNI** - build nothing until real traffic in `frisk.log` asks for it. No speculative config keys, flags, or tiers.

## Invariants

- frisk only shortcuts, never bypasses: every failure path is silence (no output, exit 0).
- Config is read only from `$XDG_CONFIG_HOME/frisk/`, never from the project.
- Reuse Claude Code vocabulary (`allow`/`ask`/`deny`/`defer`, `permissions.*`, `autoMode.*`); invent no new terms.
- Comments explain why, never what.

## Workflow

`just check` (fmt + lint + race tests) must pass before every commit. Conventional Commits.
