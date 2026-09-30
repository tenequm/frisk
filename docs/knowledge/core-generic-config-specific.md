---
type: Decision
title: Core understands commands, config decides
description: Core parses commands and screens their arguments for any unix user and ships no allow rules; which commands settle, and one user's tools, hosts and policy, live in their config.
tags: [architecture, scope]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T15:58:00Z" }
sources:
  - id: maintainer
    resource: maintainer instructions on 2026-09-30 (no durable link)
    title: Scope of the frisk core
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
---

# Decision

The code in `frisk.go` understands commands and decides nothing about them. It
ships no allow rules: with no config, every command passes through to Claude
Code's own flow. What settles, and how, is written in
`$XDG_CONFIG_HOME/frisk/config.json`.[^maintainer]

The test for anything in core: would it be correct for a stranger who installed
frisk on Linux or macOS and has not told it what they allow?

# Where things go

Core:

- Command parsing: quoting, separators, redirects, heredocs, and variables the
  command itself sets to a literal.
- The screens that keep a config rule from matching a form it does not mean. See
  [Static allow needs argument screening](static-allow-needs-argument-screening.md).
- Credential locations that are common across unix systems: `~/.ssh`, `~/.aws`,
  `.gnupg`, `.netrc`, `.npmrc`, `.pypirc`, `.env` files, key and keychain files,
  and the standard password-store directories.

Config (per user):

- Every `permissions.allow`, `ask` and `deny` rule, including the read verbs of
  ubiquitous tools such as coreutils, `git` and `kubectl`.
  `config.example.json` carries a read-only starting list to copy and trim.
- Facts about their environment for the judge: which hosts, organizations and
  directories are theirs, which branches are personal.
- Policy for a specific secret manager, for example when piping a value from a
  vault CLI into a consumer is routine and when it must prompt.

# Why

An allow list in core is a decision made for the user: it settles commands they
never said they allow, and every install inherits it.[^maintainer] A screen is
different in kind. It never produces a verdict; it only stops a rule such as
`sed *` from matching `sed -i`, so the command passes through as if the rule
were not there.[^design]

Config is read only from the user's config directory and never from the project,
so a cloned repository cannot retarget the gate.[^design]

[^maintainer]: Scope of the frisk core
[^design]: frisk design
