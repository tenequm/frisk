---
type: Finding
title: The server classifier evaluates every call, whatever the hook says
description: Claude Code's auto-mode classifier runs on the API request before any hook, so a frisk allow does not skip it; the allow only lets the tool start without waiting for the verdict.
tags: [classifier, claude-code, latency]
status: stable
stale_after: "2026-12-31T00:00:00Z"
generated: { by: claude-code/opus-5-5, at: "2026-09-30T14:21:00Z" }
sources:
  - id: measured
    resource: join of 984 Bash, Edit and Write tool calls from one machine's session transcripts on 2026-09-30 against frisk.log, Claude Code 2.1.285 in auto mode (scripts and results not committed)
    title: Classifier-after-allow measurement
  - id: bundle
    resource: Claude Code 2.1.285 client bundle, the message_delta handler that reads safeguard_results and the code that stamps serverClassifierContext on tool results
    title: Claude Code client, read locally
---

# Finding

The classifier verdict for a response's tool calls is requested with the API call
and comes back on the response stream's final `message_delta`. The PreToolUse
hook has no influence on whether that evaluation happens.[^bundle]

A hook `allow` was honoured in every observed case: 639 of 639 frisk-allowed
calls ran, and none ended in a classifier error.[^measured]

# What the transcript marker means

A tool result carries `serverClassifierContext` only when it was written after
the verdict arrived. The key is therefore a timing artifact:

- results written less than 0.75 s after the assistant message's last block
  carried it in 4 of 377 cases; results written 1.5 s or later carried it in 191
  of 203;
- in every message with several allowed calls and a mixed outcome, each result
  without the key was written before each result with it.[^measured]

Present means the server evaluated the call. Absent does not mean it was skipped.
Counting the key to measure "how often the classifier still runs after an allow"
measures how slow the commands were.

# What an allow buys

Without a hook decision the client waits for the verdict before running the
tool; the verdict lands a median 1.68 s after the message's last block. With an
allow the result of a quick command lands a median 0.47 s after it, so the tool
result is available roughly 1.2 s earlier per call.[^measured]

Whether the whole turn gets faster is not established: the client needs the final
`message_delta` anyway, so for a quick command the wait may move from before the
tool to after it.

Not observed: what happens when the server flags a call the hook allowed.

[^measured]: Classifier-after-allow measurement
[^bundle]: Claude Code client, read locally
