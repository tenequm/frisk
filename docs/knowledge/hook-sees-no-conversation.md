---
type: Finding
title: The hook sees the command, not the conversation
description: Actions whose safety depends on what the user asked for cannot be settled from command text, and they surface as low-confidence verdicts.
tags: [judge, confidence, limits]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T13:07:00Z" }
sources:
  - id: live
    resource: frisk.log from the first 23 minutes of live use on 2026-09-30, 319 verdicts across several sessions on one machine (local, not committed)
    title: First live traffic
  - id: confidence
    resource: https://docs.typesafe.ai/confidence
    title: Jev confidence
---

# Finding

A PreToolUse hook receives the tool name, the tool input and the working
directory. It does not receive the conversation. Claude Code's classifier does.
So the classifier can tell "the user asked for this pull request" from "the agent
decided to open one", and frisk cannot.

Commands in that category are judged on text alone: opening or editing a pull
request, a bare `git push`, running a binary the project just built, a script
whose body was not attached. The judge splits its probability between allow and
ask, and the verdict comes back with low confidence.

# Evidence

In the first live traffic, six of the ten prompts raised by the judge had
confidence between 0.31 and 0.47, with allow and ask nearly tied (for example
allow 0.44, ask 0.48). Five of seven judge denies were below 0.50.[^live]

Confidence here is a measure of how concentrated the probability is, not a
probability of being right.[^confidence] A near tie between allow and ask means
the text did not contain what the judge needed.

# Implications

- A low-confidence ask carries little information. Leaving it to Claude Code's
  flow, which has the conversation, costs nothing in safety relative to running
  without frisk. See
  [Weak judge verdicts are not acted on](confidence-floors.md).
- Prose can close part of the gap by stating standing intent, for example that
  opening pull requests on the user's own repositories is routine.
- Facts frisk can gather itself, such as the current branch and its upstream, turn
  some of these cases into decidable ones. Facts only the conversation holds stay
  out of reach.
- The judge appears to weigh quoted text as if it were a command. A dry run of the
  gate whose quoted argument named a push and a merge was itself sent to ask at
  0.81; the cause was inferred, not isolated.[^live]

[^live]: First live traffic
[^confidence]: Jev confidence
