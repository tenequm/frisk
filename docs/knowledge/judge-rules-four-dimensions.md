---
type: Decision
title: Judge prose is a few tests over four risk dimensions
description: The judge lists are written as tests over ownership, recoverability, secret exposure and gate integrity, within a fixed item budget, because topic-word rules and carve-out lists both failed on the regression set.
tags: [judge, prose, policy]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-10-06T18:52:00Z" }
sources:
  - id: regression
    resource: replay of 829 historical hook commands that the earlier config denied, asked or withheld as asks, through `frisk check` against three judge configurations on 2026-10-06, judge typesafe/jev-1.13 via OpenRouter (results not committed; replay state is the machine's, not the original)
    title: 829-command regression
  - id: advisors
    resource: two independent written reviews of the judge prose on 2026-10-06, one by a Fable model and one by a Codex model, given the same brief and regression results (not committed)
    title: Advisor reviews
---

# Decision

The judge lists stay small and principled. Every item is a test over four
questions the judge can answer from the command and the trusted state: whose
system the command changes, whether the user can undo it, whether a secret value
becomes readable or leaves, and whether it attacks the gate.[^advisors]

- `environment` holds facts only: what the user owns, which areas are disposable,
  what the user does every day, and that text a command stores or passes as data
  describes nothing the command does.
- `allow` names routine work in a few families, because the judge reads criteria
  literally (see [Judge prose must name routine work](judge-prose-must-name-routine-work.md)).
- `soft_deny` covers only cases that need the user's judgement and carries an
  observable trigger.
- `hard_deny` requires demonstrated harm: every condition visible, and a stated
  non-applicability when a condition cannot be read.
- Budget: at most 6 environment, 4 allow, 4 soft_deny and 3 hard_deny items. A new
  item replaces or generalizes an existing one; an item that names a specific
  command is moved to environment, to a core record or to the static allow list
  instead. There is no word cap: the item count is what keeps the lists from
  growing, and prose length costs little at the judge's input price.
- `ask` stays in `judge.decisions`: the asks the user wants (client merges, apply
  comments on client pull requests, production writes, IAM grants) are conditioned
  on ownership, which static rules cannot express.

# Why

On the same 829 problem commands:[^regression]

| Prose | Allow | Silent | Ask | Deny |
| --- | ---: | ---: | ---: | ---: |
| Compressed topic lists (24 items) | 36 | 398 | 270 | 125 |
| Same lists with narrowed denies | 57 | 482 | 270 | 20 |
| Four-dimension tests (17 items) | 218 | 464 | 141 | 6 |

Deny items built on topic words ("secret", "printed", paths like /etc) drew in any
command near those words, and "choose the strictest option" turned that partial
match into an ask or a deny. Quoted text, agent briefs and `frisk check`
arguments were judged as if executed. Adding one carve-out per false positive
recreates the long list the compressed version replaced.[^advisors]

[^regression]: 829-command regression
[^advisors]: Advisor reviews
