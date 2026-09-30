---
type: Decision
title: Config can stop the judge from prompting
description: judge.decisions lists which of allow, ask and deny the judge may issue; a user who lists only allow and deny gets no judge prompts, and the withheld verdicts stay countable in the log.
tags: [judge, config, prompts]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T14:21:00Z" }
sources:
  - id: code
    resource: repository commit 0b27374, frisk.go (judgeConfig.decisions and the withheld branch in judge)
    title: "feat(judge): let config choose which decisions the judge issues"
  - id: live
    resource: frisk.log and permission prompts from about two hours of live use on 2026-09-30 on one machine (local, not committed)
    title: Live prompts on the first day
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
---

# Decision

`judge.decisions` is a list drawn from `allow`, `ask`, `deny`. Unset means all
three. After the confidence floors have produced the judge's outcome, an outcome
the list leaves out becomes silence, and Claude Code's own flow decides.[^code]

With `["allow", "deny"]` the judge never prompts: an ask, and a deny below its
floor (which the floors turn into an ask), are both withheld. The reason and the
log row keep the verdict with the note `ask withheld by judge.decisions`, so the
prompts that would have been shown can be counted later.[^design]

The key covers the judge tier only. Config `permissions.ask` and
`permissions.deny` rules, the static tier and the file-tool guardrail asks are
unaffected. An empty list or an unknown value is a malformed config.

# Why

The judge prompts the user reported on the first day were each either a judge
misreading or a policy line the user then chose to relax.[^live] The recurring
causes were:

- quoted text read as the action itself (a dry-run of a push, a commit message
  that mentions the judge);
- a probe note for a script that did not exist (see
  [A script the judge cannot see must be reported](unseen-script-must-be-reported.md));
- prose that matched literally against routine work (see
  [Judge prose must name routine work](judge-prose-must-name-routine-work.md)).

A prompt interrupts the user, while silence only hands the call to the layer that
would have decided without frisk. For a user who wants frisk to save time, the
judge is useful for its allows and its confident denies, and its asks cost more
than they return.

The default stays all three, because a user who runs frisk as the stricter layer
wants the prompts. See
[Core is generic, config is personal](core-generic-config-specific.md).

# Cost

With asks withheld, a confirm-first action is decided by whatever sits behind
frisk. That is acceptable only while frisk front-runs the classifier. See
[frisk front-runs Claude Code's permission flow](front-run-not-bypass.md) and
[Weak judge verdicts are not acted on](confidence-floors.md). An action that must
always prompt belongs in `permissions.ask`, which the key does not touch.

[^code]: feat(judge): let config choose which decisions the judge issues
[^live]: Live prompts on the first day
[^design]: frisk design
