---
type: Decision
title: Core is generic, config is personal
description: Builtin rules must be right for any user on Linux or macOS; one user's tools, hosts and secret-handling policy live in their config.
tags: [architecture, scope]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T13:07:00Z" }
sources:
  - id: maintainer
    resource: maintainer instruction on 2026-09-30 (no durable link)
    title: Scope of the frisk core
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
---

# Decision

The code in `frisk.go` is a set of checks that apply to anyone on a unix system.
Anything specific to one person's setup goes in
`$XDG_CONFIG_HOME/frisk/config.json`.[^maintainer]

The test for a builtin: would this rule be correct for a stranger who installed
frisk with `go install` on Linux or macOS?

# Where things go

Core (builtins):

- Command parsing and the screens that stop a read-only verb from being waved
  through. See
  [Static allow needs argument screening](static-allow-needs-argument-screening.md).
- Credential locations that are common across unix systems: `~/.ssh`, `~/.aws`,
  `.gnupg`, `.netrc`, `.npmrc`, `.pypirc`, `.env` files, key and keychain files,
  and the standard password-store directories.
- Read verbs of ubiquitous tools such as coreutils, `git` and `kubectl`.

Config (per user):

- The user's own CLIs and wrappers, as `permissions.allow`, `ask` or `deny` rules.
- Facts about their environment for the judge: which hosts, organizations and
  directories are theirs, which branches are personal.
- Policy for a specific secret manager, for example when piping a value from a
  vault CLI into a consumer is routine and when it must prompt.

# Why

Config is read only from the user's config directory and never from the project,
so a cloned repository cannot retarget the gate.[^design] The same separation
keeps the core honest in the other direction: a builtin that encodes one person's
tools is wrong for everyone else and widens what every install allows.

[^maintainer]: Scope of the frisk core
[^design]: frisk design
