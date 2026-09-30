---
type: Finding
title: Bash and zsh read a variable of several words differently
description: Bash splits an unquoted variable into words and zsh keeps it whole, so a static allow must pass both readings, and in zsh a command variable holding a path with a space runs that path.
tags: [static-tier, shell, variables]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T18:00:00Z" }
sources:
  - id: pond
    resource: count over Bash tool calls in the maintainer's agent session history (pond), 2026-09-30 (no durable link)
    title: Session history count
  - id: planted
    resource: reproduction under `zsh -f` with a planted executable, 2026-09-30 (no durable link)
    title: zsh path execution check
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
---

# Finding

`C="cuttle --name box pw"; $C snapshot` runs `cuttle` with three arguments in
bash, and in zsh tries to run a program literally named `cuttle --name box pw`.
frisk cannot know which shell runs a command, so a static allow has to be
right for both readings: bash's fields and zsh's single word.[^design]

In agent traffic the shape is real but not common: 611 Bash calls in 234
sessions assigned a literal value of several words and used it, about 0.15% of
calls. Of the 32 that used it in command position, none worked in zsh: 24 show
`command not found`, or `no such file or directory` when the value held a
`/`.[^pond]

With a `/` in the value zsh does not look the name up on `PATH`; it executes the
path as written. A file planted at `./git -C /tmp/repo log` ran when
`C="git -C /tmp/repo log"; $C --oneline` was run under `zsh -f`.[^planted]

# Rule

- Read a variable of several plain words both ways, and allow statically only if
  both readings pass every screen and every segment matches a rule.
- In zsh's reading, a command word with a space and no `/` names no program, so
  that segment runs nothing. With a `/` in it, the command does not settle.
- Inside double quotes both shells keep one word; a word mixing quoted and
  unquoted parts is left unresolved.

[^pond]: Session history count
[^planted]: zsh path execution check
[^design]: frisk design
