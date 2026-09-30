---
type: Finding
title: Static allow needs argument screening
description: A read-only verb rule is not a safe allow on its own; arguments, flags, environment assignments, globs, shell quoting and variables can turn a reader into a writer, an executor or a secret leak.
tags: [static-tier, safety]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T15:58:00Z" }
sources:
  - id: fix
    resource: repository commit 9b552c2, frisk.go and frisk_test.go
    title: "fix(static): close credential-path, flag, env-prefix, and glob allow holes"
  - id: audit
    resource: audit of the read-only allow rules on 2026-09-30, each case confirmed with `frisk check` (no durable link)
    title: Static-tier audit
  - id: tokenizer
    resource: review of the tokenizer on 2026-09-30, each case confirmed with `frisk check` before it was closed (no durable link)
    title: Tokenizer audit
---

# Finding

The static tier allows a command when every segment matches a
`permissions.allow` rule such as `cat *` or `git fetch *`. Matching the verb is
not enough. Each class below was a static allow before it was
closed.[^audit][^fix][^tokenizer]

| Class | Example | Why it is not a read |
|---|---|---|
| Credential path as an argument | `cat ~/.ssh/id_rsa` | The verb reads, the target is a secret |
| Rule wider than its read subcommands | `git -C repo remote add x url` matched `git -C * remote *` | Mutating subcommand under a read pattern |
| Flag that runs a program | `fd . -x rm {}`, `rg --pre=sh x`, `git fetch --upload-pack=cmd` | The reader executes something else |
| Flag that writes, in attached form | `sed -i.bak ...`, `sort -oFILE` | Exact-match flag checks miss attached values |
| Program text loaded from a file | `jq -f prog.jq`, `jq 'include "m"; .'` | The program screen never sees the text |
| Environment assignment | `GIT_SSH_COMMAND=x git fetch`, `HOME=. git status`, `LESS=-o/tmp/x less f` | The assignment makes the verb run or load something else |
| Glob that expands to a secret | `cat ~/.ss*/id_*` | The path screen saw the unexpanded token |
| Brace list or glob qualifier | `find . {-delete,-print}`, zsh `ls *(e:'id':)` | One word becomes several, or runs code, after the screens ran |
| Reader of the environment | `printenv`, `env`, `echo $GITHUB_TOKEN`, `gh pr list --jq env` | Prints secrets held in variables |
| Variable in argument position | `fd . $ARGS`, `ls $1` | The value can be a flag, a credential path or several words |
| Quoting read differently from the shell | an escaped `"` inside double quotes, a backslash-newline inside a flag, `$'-x'` | The commands or flags that follow were taken for quoted text |

# Rule

A segment is statically allowed only if a rule matches and none of its tokens
trips a screen: credential paths, write and exec flags including abbreviated and
attached forms, program text and the flags that load it from a file, assignments
that hijack the shell or a child process, credential-shaped globs and brace
lists, references to secret-named variables, and any expansion the command does
not itself set to a literal. The screens run on the words the shell will see,
which means the tokenizer has to agree with the shell about quoting first.

A screen that fires never produces a deny. It only withdraws the static allow, so
the judge or Claude Code's own flow decides. False positives are therefore cheap
and the screens can be conservative.[^fix]

Allow rules, in `config.example.json` or a user's own config, should be written
as the narrow read forms of a tool, never as `tool subcommand *` when the
subcommand has mutating children. A rule for a verb that core has no screen for
allows every form of it.

[^fix]: fix(static): close credential-path, flag, env-prefix, and glob allow holes
[^audit]: Static-tier audit
[^tokenizer]: Tokenizer audit
