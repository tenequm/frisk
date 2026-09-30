---
type: Decision
title: Weak judge verdicts are not acted on
description: A judge allow below 0.75, an ask below 0.50 or a deny below 0.50 is downgraded rather than enforced, because low-confidence verdicts were mostly wrong in live use.
tags: [judge, confidence, thresholds]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T13:18:00Z" }
sources:
  - id: code
    resource: repository commit 091465e, frisk.go (the confidence floor constants and the judge verdict mapping)
    title: "feat: probe scripts behind wrappers, explain judge verdicts, close static holes"
  - id: live
    resource: frisk.log from the first 23 minutes of live use on 2026-09-30, 319 verdicts across several sessions on one machine (local, not committed)
    title: First live traffic
  - id: scripts
    resource: script-judgment harness run on 2026-09-30, 100 corpus cases and 33 synthetic cases (results not committed)
    title: Script-body judging harness
  - id: confidence
    resource: https://docs.typesafe.ai/confidence
    title: Jev confidence
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
---

# Decision

The judge's answer is enforced only when it is confident:[^code]

| Judge says | Confidence | frisk does |
|---|---|---|
| allow | 0.75 or above | allow |
| allow | below 0.75 | silence |
| ask | 0.50 or above | ask |
| ask | below 0.50 | silence |
| deny | 0.50 or above | deny |
| deny | below 0.50 | ask |

Static `deny` and `ask` rules from config are not affected; they always apply.

# Why

Jev's confidence measures how concentrated the probability is across the
options.[^confidence] A low value means the command text did not contain what the
judge needed, which is the normal case for actions that depend on the
conversation. See
[The hook sees the command, not the conversation](hook-sees-no-conversation.md).

- In the first live traffic, six of ten judge prompts sat between 0.31 and 0.47
  with allow and ask nearly tied, and five of seven judge denies were below 0.50.
  Two of those weak denies blocked agents making routine edits in their own
  worktree (0.24 and 0.30).[^live]
- On 100 real script-running commands, 21 of 46 ask or deny verdicts were below
  0.50, ten of them denies.[^scripts]
- The 0.75 allow floor predates the others: injected approval claims were measured
  dragging an allow down to about 0.68.[^design]

The mapping is asymmetric on purpose. A weak ask is dropped, because Claude Code's
own flow has the conversation and decides better. A weak deny is turned into a
prompt, because a judge leaning toward deny deserves a human look but not a hard
block.

# Cost

A weak ask on something risky is no longer shown to the user; it goes to whatever
sits behind frisk. That is acceptable only while frisk front-runs the classifier.
See [frisk front-runs Claude Code's permission flow](front-run-not-bypass.md).

The three numbers are facts about `jev-1.13.0` with the prose in use at the time.
They need re-measuring when the model pin or the judge prose changes materially.

[^code]: feat: probe scripts behind wrappers, explain judge verdicts, close static holes
[^live]: First live traffic
[^scripts]: Script-body judging harness
[^confidence]: Jev confidence
[^design]: frisk design
