---
type: Decision
title: Core ships generic defaults, config adds the user's facts
description: Like Claude Code, core ships a measured read-only allow baseline and generic judge prose that any unix user can run; one user's tools, hosts, ownership and policy live in their config, which extends the judge prose with "$defaults".
tags: [architecture, scope]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-10-07T09:45:00+01:00" }
sources:
  - id: maintainer
    resource: maintainer instructions on 2026-10-07 (no durable link)
    title: Scope of the frisk core
  - id: claude-code
    resource: https://code.claude.com/docs/en/permissions#read-only-commands
    title: Claude Code permissions, read-only commands
  - id: coverage
    resource: replay of 21,043 logged hook Bash calls from one machine's frisk.log, 2026-09-23 to 2026-10-07, through `frisk check` with the judge off, under a 40-rule and a 117-rule read-only list (results not committed)
    title: Baseline coverage measurement
---

# Decision

frisk follows Claude Code's split.[^maintainer] Claude Code ships a built-in,
non-configurable set of read-only Bash commands that run without a prompt, which
`ask` and `deny` rules override, and classifier prose that config extends with
`"$defaults"`; its `permissions.allow` has no defaults.[^claude-code]

Core ships:

- `builtinAllow`, a read-only static baseline. It always applies,
  `permissions.ask` and `permissions.deny` override it, and a static reason ends
  in `(builtin)` when one of its rules matched.
- `builtinJudge`, generic judge prose. Each judge list extends it with
  `"$defaults"`, spliced in place, or replaces it by leaving the marker out.
- The parser and the screens, which keep any allow rule, builtin or configured,
  from matching a form it does not mean.

Config holds what is one user's: extra allow rules, ask and deny rules, and the
facts the prose cannot know - which repositories, hosts and organizations are
theirs, extra working areas, their daily work, policy for systems they operate
for others.

# What qualifies for core

The test: would it be right for a stranger on Linux or macOS who has not told
frisk anything?

- A baseline rule must be read-only under the screens and settle real traffic.
  Forty rules settle 9,154 of 21,043 logged calls (43.5%); the 117-rule
  read-only list the example once carried settles 9,346 (44.4%).[^coverage]
  Rules that can print a secret in normal use stay out: `git config` and
  `git remote -v` (a token in a remote URL), `printenv`.
- Builtin prose makes no ownership claim. A generic "the working directory's
  remotes are the user's own" would contradict a user's own fact that a client
  repository is not theirs, and a command that half-fits two items scores low
  on both. Without ownership facts, items that depend on them resolve to
  silence, never to a wrong allow.
- Builtin prose may name widely used secret sources (`gopass show`, `op read`,
  `security find-*-password`): the exposure rule never fires without concrete
  sources (see [Secret rules name the destination](secret-rules-name-the-destination.md)).
- It assumes a single developer's own machine with an agent proposing commands.
  A user in another setting replaces the environment list.

# Why

Defaults that ship with the binary stay in step with what the binary sends the
judge: the prose decides git commands from `git.commands` records and treats
listed `data` as content, and only core knows when those records change. Before
this decision the measured prose lived in one user's config while core kept
unmeasured one-liners, and the example inherited the weak ones.[^maintainer]

Config is read only from the user's config directory and never from the
project, so a cloned repository cannot retarget the gate.

[^maintainer]: Scope of the frisk core
[^claude-code]: Claude Code permissions, read-only commands
[^coverage]: Baseline coverage measurement
