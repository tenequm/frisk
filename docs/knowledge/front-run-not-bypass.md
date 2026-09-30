---
type: Decision
title: frisk front-runs Claude Code's permission flow
description: frisk runs in front of auto mode and never as the only gate under bypassPermissions, because in that mode every frisk failure path would become an allow.
tags: [architecture, safety]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T13:07:00Z" }
sources:
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
  - id: cost
    resource: repository file ops/classifier-data/2609-29-classifier-cost-analysis.md
    title: Classifier cost analysis
  - id: discussion
    resource: design discussion with the maintainer on 2026-09-30 (no durable link)
    title: Migration discussion
---

# Decision

frisk is deployed as a PreToolUse hook with Claude Code left in auto mode. It
answers first; whatever it does not answer goes to Claude Code's own rules and
classifier exactly as before. It is not deployed as a replacement for that flow
under `bypassPermissions`.[^discussion]

# Why

Every frisk failure path is silence: bad config, missing key, judge timeout,
malformed answer, low confidence, a judge `defer`.[^design] Silence is safe only
because something sits behind it.

- In auto mode, silence means the classifier decides. The worst case is the
  behavior from before frisk was installed.
- Under `bypassPermissions` nothing sits behind it, so silence means the command
  runs. A judge outage would quietly allow every command the static tier cannot
  settle. That is fail-open, and the invariant "every failure path is silence" was
  not written for it.

Replacing the classifier outright would first require changing that invariant, so
that judge failures and defers return `ask` instead of silence.

# What this buys and what it does not

frisk saves the classifier round trip only for calls it answers. The cost
analysis measured that 3 to 10 percent of hook allows still triggered the
classifier anyway, so the saving depends on the harness honoring a hook
`allow`.[^cost]

DESIGN.md states that a frisk `deny` or `ask` is honored in every mode, including
`bypassPermissions`.[^design] That claim has not been tested here.

[^design]: frisk design
[^cost]: Classifier cost analysis
[^discussion]: Migration discussion
