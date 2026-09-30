---
type: Finding
title: Static allow needs argument screening
description: A read-only verb list is not a safe allow rule; arguments, flags, environment prefixes and globs can turn a reader into a writer, an executor or a secret leak.
tags: [static-tier, safety]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T13:07:00Z" }
sources:
  - id: fix
    resource: repository commit 9b552c2, frisk.go and frisk_test.go
    title: "fix(static): close credential-path, flag, env-prefix, and glob allow holes"
  - id: audit
    resource: audit of the builtin allow list on 2026-09-30, each case confirmed with `frisk check` (no durable link)
    title: Static-tier audit
---

# Finding

The static tier allows a command when every segment matches a rule such as
`cat *` or `git fetch *`. Matching the verb is not enough. Each class below was a
static allow before it was closed.[^audit][^fix]

| Class | Example | Why it is not a read |
|---|---|---|
| Credential path as an argument | `cat ~/.ssh/id_rsa` | The verb reads, the target is a secret |
| Rule wider than its read subcommands | `git -C repo remote add x url` matched `git -C * remote *` | Mutating subcommand under a read pattern |
| Flag that runs a program | `fd . -x rm {}`, `rg --pre=sh x`, `git fetch --upload-pack=cmd` | The reader executes something else |
| Flag that writes, in attached form | `sed -i.bak ...`, `sort -oFILE` | Exact-match flag checks miss attached values |
| Environment assignment prefix | `GIT_SSH_COMMAND=x git fetch`, `LESSOPEN=x less f` | The prefix was stripped before matching |
| Glob that expands to a secret | `cat ~/.ss*/id_*` | The path screen saw the unexpanded token |
| Reader of the environment | `printenv`, `env`, `echo $GITHUB_TOKEN` | Prints secrets held in variables |

# Rule

A segment is statically allowed only if its verb matches and none of its tokens
trips a screen: credential paths, write and exec flags including abbreviated and
attached forms, environment prefixes that hijack a child process, credential-shaped
globs, and references to secret-named variables.

A screen that fires never produces a deny. It only withdraws the static allow, so
the judge or Claude Code's own flow decides. False positives are therefore cheap
and the screens can be conservative.[^fix]

New builtin allow patterns should be written as the narrow read forms of a tool,
never as `tool subcommand *` when the subcommand has mutating children.

[^fix]: fix(static): close credential-path, flag, env-prefix, and glob allow holes
[^audit]: Static-tier audit
