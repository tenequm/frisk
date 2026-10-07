---
type: Finding
title: A files-written facts record does not lift the judge on inline edits
description: A trusted record of the files an inline python, sed -i or cat > command writes left judge verdicts on real traffic within run-to-run noise, because most real edit scripts loop or define helpers and resolve to unknown, and an unknown record pushes the judge toward ask.
tags: [judge, trusted-state, inline-scripts, eval]
status: stable
generated: { by: claude-code/fable-5, at: "2026-10-07T18:55:00Z" }
sources:
  - id: measure
    resource: fresh `frisk check` of 203 hook commands logged on 2026-10-07 (138 inline python, 45 sed -i, 20 cat >) from each command's original working directory, live judge, one user's config (results not committed)
    title: Installed build vs facts-record builds on one day of inline edits
  - id: branch
    resource: branch feat/write-facts-record, commit f7e114b (unmerged)
    title: "feat: give the judge facts about files a command writes"
---

# Finding

The record (paths written with an inside/outside/unresolved scope, Python
imports, process/network/delete/dynamic-code risk flags, an unknown bit) was
built with a Go lexer: no Python executed, unknown on anything it could not
resolve.[^branch] On one day of real traffic:[^measure]

| Build | allow | ask | silent |
|---|---|---|---|
| Without the record, run 1 | 37 | 10 | 156 |
| Without the record, run 2 | 44 | 8 | 151 |
| Record as committed | 3 | 38 | 162 |
| Record omitted when unknown, absolute paths instead of `outside` | 45 | 13 | 145 |

- 143 of 203 commands resolved to unknown: real edit scripts loop over files
  (87 of 138 python scripts contain `for`) and define helpers, which a lexer
  cannot follow without becoming an interpreter.
- An unknown or `outside` record is read as a warning, so sending one is worse
  than sending none. `outside` fired whenever the agent changed directory away
  from the hook's working directory, even into another working area.
- With unknown records withheld and scope left to the environment prose, the
  gain was inside the judge's run-to-run noise (two runs of the same build
  differed on 21 of 203 verdicts). Risky negatives still asked or stayed below
  the floor.

# Consequence

Facts records help where the facts are cheap and complete, as git's are. For
inline code the resolvable cases are the simple ones the judge already allows,
so the record adds code without moving verdicts. The branch stays unmerged.
