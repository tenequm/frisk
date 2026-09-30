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
- [Core is generic, config is personal](core-generic-config-specific.md) - Builtin
  rules must be right for any user on Linux or macOS; one user's tools, hosts and
  secret-handling policy live in their config.
- [Weak judge verdicts are not acted on](confidence-floors.md) - A judge allow
  below 0.75, an ask below 0.50 or a deny below 0.50 is downgraded rather than
  enforced, because low-confidence verdicts were mostly wrong in live use.

## Findings

- [Judge prose must name routine work](judge-prose-must-name-routine-work.md) - Jev
  applies criteria literally, so allow prose that only describes read-only
  inspection turns ordinary development into prompts and blocks.
- [The hook sees the command, not the conversation](hook-sees-no-conversation.md) -
  Actions whose safety depends on what the user asked for cannot be settled from
  command text, and they surface as low-confidence verdicts.
- [Static allow needs argument screening](static-allow-needs-argument-screening.md) -
  A read-only verb list is not a safe allow rule; arguments, flags, environment
  prefixes and globs can turn a reader into a writer, an executor or a secret leak.
- [A script the judge cannot see must be reported](unseen-script-must-be-reported.md) -
  When a command runs a script whose body is not attached, the judge rates the
  harmless-looking command line and allows it, so the probe must follow the command
  to the real file and say so when it cannot.

## References

- [Jev API facts frisk depends on](jev-api-facts.md) - Pricing, limits, context
  size, how confidence is computed and measured latency for the pinned judge model.
