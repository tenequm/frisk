---
type: Finding
title: Replaying logged commands skews verdicts through trusted state
description: A replay sends the judge the replay machine's git facts and probe results, not the ones the command originally ran with, so ask and deny rates from a replay overstate what live traffic gets.
tags: [eval, replay, judge, probe]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T14:21:00Z" }
sources:
  - id: replay
    resource: replay of 1,519 classifier-allowed corpus commands through `frisk check` on 2026-09-30, from one working directory on one machine (results not committed)
    title: Corpus replay after the probe and git-facts change
  - id: code
    resource: repository commit 091465e, frisk.go (gitFacts and probeScripts, both resolved from the hook's working directory)
    title: "feat: probe scripts behind wrappers, explain judge verdicts, close static holes"
---

# Finding

Since the judge request carries trusted state, a command's verdict depends on
where and when it is evaluated, not only on its text:[^code]

- git facts (branch, upstream, default branch, remote) are read from the working
  directory of the process doing the replay, so every replayed `git push` is
  judged as a push from that repository and branch;
- the script probe looks for files that existed when the command first ran. At
  replay time most are gone, so the probe reports `missing` and the judge is told
  a script body could not be attached.

In one replay 76 of 167 asks carried a "not attached" note only because the
script no longer existed; the ask rate was 11.0% as measured and about 6% with
those excluded.[^replay]

# Consequence

A replay is sound for the static tier, which reads only the command text. For the
judge tier it gives an upper bound on asks and denies, and it cannot evaluate
rules that depend on the repository or on a script body.

To tune those rules, use fixtures that pin the trusted state, or dry-run the
command from the directory it belongs to while its files still exist.

[^replay]: Corpus replay after the probe and git-facts change
[^code]: feat: probe scripts behind wrappers, explain judge verdicts, close static holes
