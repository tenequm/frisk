---
type: Decision
title: Core describes git, prose decides
description: frisk sends the judge a trusted record for each git command (class, forcing, push destination, files a discard would lose) and decides nothing by rule; judge prose, builtin and the user's, is written against the record's fields.
tags: [git, judge, architecture]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-10-07T09:45:00+01:00" }
sources:
  - id: maintainer
    resource: maintainer instructions on 2026-09-30 (no durable link)
    title: How frisk should treat git
  - id: design
    resource: repository file DESIGN.md
    title: frisk design
  - id: eval
    resource: live run of `just eval-git` on 2026-09-30, 103 fixtures in testdata/git-fixtures.jsonl with pinned repository state (no durable link)
    title: Git record measurement
  - id: eval831
    resource: 5-run judge evaluation of 831 labeled commands on 2026-10-06 (results not committed)
    title: Labeled-command judge evaluation
---

# Decision

Core understands git and decides nothing about it. For every git segment of a
command the judge receives one record under `state.git.commands`: the
subcommand, a class (`read`, `local`, `discard`, `remote`, `exec`, `unknown`),
whether it forces, deletes a ref or skips hooks, where a push goes and whether
that is the remote's default branch, and how many files a discard would
lose.[^design] What to do with those facts is `judge` prose: the builtin prose
allows reads, local work and unforced pushes by record and asks about forced
pushes and discards that lose files, and the user's ownership facts say which
repositories and branches are theirs. A list that replaces the builtins without
any prose about git leaves git commands to pass through like any
other.[^maintainer]

A field that cannot be determined says `unknown`. It is never guessed and never
resolved toward the permissive value.

# Why not rules in core, or a pattern list

- A class table in core that allowed or denied by itself would bypass the
  judge and the user's facts: whether a push is acceptable depends on whose
  repository and branch it is, which only config knows (see
  [Core ships generic defaults](core-generic-config-specific.md)).[^maintainer]
- "Allow all git, deny a few patterns" leaks: git runs programs through
  `-c alias.x=!cmd`, `--exec` and `bisect run`, positional rules miss reordered
  flags, and whether a push is acceptable depends on the remote and the
  destination branch, which are not in the words.
- Judge prose about wording ("git push --force or --force-with-lease, deleting
  remote branches ...") makes the judge infer facts from text. The same policy
  keyed on record fields is both stricter and more confident.

# What was measured

On fixtures that each build a repository with known state, the judge was given
the same policy twice: as prose about wording with no record, and as prose
written against the record.[^eval]

| | Correct of 102 | Wrong allow | Silent | Unexpected ask | Median confidence |
|---|---|---|---|---|---|
| No record | 66 | 1 | 25 | 10 | 0.80 |
| Record | 82 | 1 | 15 | 4 | 0.93 |

Re-running one arm flips 1 to 7 of 99 outcomes at the confidence floors, so
differences of a few fixtures between arms are noise.

Asking the judge a two-way question (allow or deny, no ask) was measured in the
same run and rejected. It gave no gain once the prose keyed on the record, and
it cannot express the cases the user wants asked about: with soft-deny prose
sent as deny criteria it denied all 12 forced-push and ref-deletion fixtures, and
with that prose dropped it allowed a forced push to a default branch.[^eval]

# Consequences

- A subcommand missing from the table is class `unknown`, and prose that decides
  by class then has nothing to allow it with. A read such as `git shortlog` went
  from a confident allow to silence until it was added, so the table has to
  cover the read subcommands people actually use.
- A record describes the repository before the command runs. Facts that an
  earlier segment of the same command may have changed are reported as
  `unknown`: a push that goes by the checked-out branch after a `switch`, a
  discard's file counts after anything but a `cd` or a git read.
- A discard record counts what the command could destroy: a `clean` with
  `-x` or `-X` also carries `ignored_files`, since `-x` deletes ignored files
  along with untracked ones and `-X` only them.
- The same split covers text a command does not run. Commit messages, PR
  bodies, briefs written through a heredoc and the commands given to
  `frisk check` were read by the judge as actions, a leading cause of
  unwanted prompts in the labeled evaluation.[^eval831] Core does not decide
  that such text is harmless; it lists where it is (`state.data`, by program,
  flag or heredoc delimiter, never a copy of the text) and the prose says
  what to do with it. Core lists only what it can settle from the words: a
  value in a statement with no substitution before it, a literal heredoc fed
  to `cat` into a file no other statement names or to git as a message. A
  heredoc fed to `ssh`, an interpreter or any other program that may run it
  stays unlisted, and the instruction says a listed file may still run later.
- The same understanding serves the user's own rules: a git rule matches the
  command git runs, not its spelling. Global options such as `-C dir` are set
  aside, flags match anywhere with short, long and bundled forms unified, and
  an allow rule never covers a force, deletion or hook-skipping flag it does
  not name. A user writes `git commit --no-verify *` once instead of one
  positional variant per flag position. `-c` and `--config-env` change what
  git runs, so a command carrying them matches only a rule that names them.

[^maintainer]: How frisk should treat git
[^design]: frisk design
[^eval]: Git record measurement
[^eval831]: Labeled-command judge evaluation
