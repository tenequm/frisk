---
okf_version: "0.2"
title: frisk knowledge base
description: Decisions, findings and references behind frisk's design that are not derivable from the code or git history.
---

# frisk knowledge base

This bundle holds what was decided about frisk and why, what was measured, and
external facts the design depends on. Read it when a change touches the static
tier, the judge request, or the split between core and config.

What stays out:

- State. Test counts, coverage of the current build, open bugs and in-flight work
  live in git, the test suite and `frisk.log`. A number belongs here only when the
  number is the finding.
- Secrets, and anything private to one machine: real command lines, host names,
  repository names, key material.
- Standing orders. Those live in [AGENTS.md](../../AGENTS.md), one line each,
  linking here for the rationale.

Conventions:

- Types: `Decision`, `Finding`, `Reference`.
- One concept per file, flat in this directory, named by topic with no date prefix,
  because a concept is rewritten in place when the facts change and deleted when it
  stops being true.
- This index is maintained by hand: one bullet per concept, reusing its
  `description`. Update it in the same change that adds, renames or deletes a
  concept.

## Decisions

- [frisk front-runs Claude Code's permission flow](front-run-not-bypass.md) - frisk
  runs in front of auto mode and never as the only gate under bypassPermissions,
  because in that mode every frisk failure path would become an allow.
- [Core ships generic defaults, config adds the user's facts](core-generic-config-specific.md) -
  Like Claude Code, core ships a measured read-only allow baseline and generic
  judge prose that any unix user can run; one user's tools, hosts, ownership and
  policy live in their config, which extends the judge prose with "$defaults".
- [Weak judge verdicts are not acted on](confidence-floors.md) - A judge allow
  below 0.75, an ask below 0.50 or a deny below 0.50 is downgraded rather than
  enforced, because low-confidence verdicts were mostly wrong in live use.
- [Config can stop the judge from prompting](judge-decisions-can-withhold-prompts.md) -
  judge.decisions lists which of allow, ask and deny the judge may issue; a user
  who lists only allow and deny gets no judge prompts, and the withheld verdicts
  stay countable in the log.
- [Core describes git, prose decides](core-describes-git-config-decides.md) -
  frisk sends the judge a trusted record for each git command (class, forcing,
  push destination, files a discard would lose) and decides nothing by rule;
  judge prose, builtin and the user's, is written against the record's fields.
- [Chained commands are judged whole](chains-are-judged-whole.md) - Judging each
  piece of a chain separately and keeping the strictest verdict moved as many
  chains out of allow as into it, at 1.8 times the judge calls, and loses the
  context that links the pieces.

- [Judge prose is a few tests over four risk dimensions](judge-rules-four-dimensions.md) -
  The judge lists are written as tests over ownership, recoverability, secret
  exposure and gate integrity, within a fixed item budget, because
  topic-word rules and carve-out lists both failed on the regression set.

## Findings

- [Static allow rules are a speed cache with a ceiling near half of all calls](static-allow-is-a-speed-cache.md) -
  A few dozen high-volume rules settle about half of real Bash calls; most of the
  rest have a shape no static rule can settle, so the judge prose, not the allow
  list, decides the interruption rate.

- [Judge prose must name routine work](judge-prose-must-name-routine-work.md) - Jev
  applies criteria literally, so allow prose that only describes read-only
  inspection turns ordinary development into prompts and blocks.
- [Secret rules must name the destination, not the act](secret-rules-name-the-destination.md) -
  Judge prose that forbids handling or moving secrets blocks routine transfers
  between a user's own stores; prose that forbids a secret becoming readable, or
  reaching a named kind of outside destination, does not.
- [The hook sees the command, not the conversation](hook-sees-no-conversation.md) -
  Actions whose safety depends on what the user asked for cannot be settled from
  command text, and they surface as low-confidence verdicts.
- [Static allow needs argument screening](static-allow-needs-argument-screening.md) -
  A read-only verb rule is not a safe allow on its own; arguments, flags,
  environment assignments, globs, shell quoting and variables can turn a reader
  into a writer, an executor or a secret leak.
- [A script the judge cannot see must be reported](unseen-script-must-be-reported.md) -
  When a command runs a script whose body is not attached, the judge rates the
  harmless-looking command line and allows it, so the probe must follow the command
  to the real file and say so when it cannot.
- [The server classifier evaluates every call, whatever the hook says](classifier-runs-regardless-of-hook.md) -
  Claude Code's auto-mode classifier runs on the API request before any hook, so a
  frisk allow does not skip it; the allow only lets the tool start without waiting
  for the verdict.
- [Replaying logged commands skews verdicts through trusted state](replays-are-skewed-by-trusted-state.md) -
  A replay sends the judge the replay machine's git facts and probe results, not
  the ones the command originally ran with, so ask and deny rates from a replay
  overstate what live traffic gets.
- [Bash and zsh read a variable of several words differently](shells-disagree-on-word-splitting.md) -
  Bash splits an unquoted variable into words and zsh keeps it whole, so a static
  allow must pass both readings, and in zsh a command variable holding a path
  with a space runs that path.
- [A files-written facts record does not lift the judge on inline edits](write-facts-do-not-lift-the-judge.md) -
  A trusted record of the files an inline python, sed -i or cat > command writes
  left judge verdicts on real traffic within run-to-run noise, because most real
  edit scripts loop or define helpers and resolve to unknown, and an unknown record
  pushes the judge toward ask.

## References

- [Jev API facts frisk depends on](jev-api-facts.md) - Pricing, limits, context
  size, how confidence is computed and measured latency for the pinned judge model.
- [The judge request is served by more than one vendor](system-one-backends.md) -
  TypeSafe's System One request shape is also served by OpenRouter, for Jev and for
  other vendors' decision models, so the backend is configuration; calibration
  differs per model.
