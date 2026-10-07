# Built-in defaults: read-only baseline and generic judge prose

Status: approved 2026-10-07, in progress on `feat/builtin-defaults`.

## Problem

Judge prose lived in three unsynced places:

- `builtinJudge` in `frisk.go`: one-line items from the initial commit, never
  measured. Its shape (read-only allow, broad ask) is the worst row in
  [Judge prose must name routine work](../knowledge/judge-prose-must-name-routine-work.md):
  about a third of classifier-allowed commands turned into asks.
- `config.example.json`: `"$defaults"` plus one line per list, so every new user
  inherits the weak builtins.
- The maintainer's own config: a measured rewrite (about 10.6% asks) that
  replaces every builtin list and never reached the repo.

The 2026-09-30 "core ships no policy" decision removed the builtin allow list but
left the builtin judge prose, which is policy too.

## Decision

Follow Claude Code. Claude Code ships a built-in, non-configurable set of
read-only Bash commands and `autoMode` classifier prose that config extends with
`"$defaults"`; `permissions.allow` has no defaults. frisk does the same:

1. Core ships a small read-only static allow baseline. It always applies;
   `permissions.ask` and `permissions.deny` override it; config adds to it.
2. Core ships the generic, measured judge prose as `builtinJudge`. Config extends
   it with `"$defaults"` or replaces a list by leaving the marker out.
3. `"$defaults"` exists only in the judge lists.

## Changes

### Read-only baseline (40 rules)

Measured on 21,043 logged hook calls (2026-09-23 to 2026-10-07, judge off):
these 40 settle 9,154 calls (43.5%); the 117-rule read-only list of the old
example settles 9,346 (44.4%). 34 rules settled at least 20 calls each; 6 more
(`pwd`, `find`, `which`, `diff`, `stat`, `du`) are in Claude Code's own set.

```
head * | sed * | rg * | cat * | cut * | tail * | wc * | ls * | jq * | echo *
grep * | fd * | uniq * | date * | awk * | sort * | cd * | sleep * | tr * | type *
pwd | find * | which * | diff * | stat * | du *
git diff * | git log * | git status * | git show * | git rev-parse * | git ls-tree *
gh pr view * | gh pr checks * | gh pr list * | gh pr diff * | gh run list *
gh run view * | gh release view * | gh api *
```

Left out on purpose: `git config` and `git remote -v` (print a token embedded in
a remote URL), `git fetch` (writes refs over the network), `printenv` (prints
secret values), `kubectl`, `gopass`, `go`, `just`, `Edit(...)` write rules.

- The static tier matches the baseline plus `permissions.allow`; deny and ask
  rules still run first.
- A static reason names a builtin match: `... allow rule: head * (builtin)`.
- `frisk validate` reports the builtin rule count; "nothing is allowed
  statically" messages change to "only the builtin read-only rules apply".
- `"$defaults"` in `permissions.*`: still loads and is ignored; the validate
  warning says the builtin rules always apply.

### Builtin judge prose (15 items)

Ported from the maintainer's config with names removed. No ownership claims:
which repositories, hosts and organizations are the user's comes only from
config. Without ownership facts, ownership-dependent items resolve to silence,
not to a wrong allow.

- environment: agent framing (verbatim); working areas defined generically (the
  working directory and its repository, directories under version control, temp
  dirs, caches) plus the recoverability facts and a line that a working area
  says nothing about ownership; text is content, not action
  (verbatim); trusted records and secret semantics (verbatim).
- allow: reading and everyday PR/CI collaboration (de-named); routine
  development of the user's own things (helmfile dropped); a secret moved
  without being displayed (verbatim); git by record (verbatim).
- soft_deny: changing a system the user does not own (de-named: no
  organizations, hosts or atlantis); irreversible loss or standing access
  (verbatim); writing the live gate (path-neutral, frisk-developer exemptions
  dropped); a concrete unresolvable risk (verbatim).
- hard_deny: demonstrated credential exposure, hook bypass or gate disable,
  wholesale destruction (all verbatim; the secret-manager names stay because the
  rule never fires without them, see
  [Secret rules name the destination](../knowledge/secret-rules-name-the-destination.md)).

Splicing is unchanged: in-place at the marker, autoMode semantics. Positional
`r1..rN` rule ids stay; the log's `reason` carries the rule text.

### Screens the baseline needed

The polish review found forms the screens let through for anyone whose config
listed these verbs; the baseline would have opened them for everyone:
`sed -l` (BSD takes no value, hiding a `w FILE` script), `uniq - FILE`, git aimed
outside the working directory (`-C`, `cd`, `--git-dir`, `--work-tree`), recursive
reads of home, its parents or its hidden directories, and awk `ARGV`. None of
them settles statically now.

### config.example.json

- `permissions.allow`: the old list minus the 40 baseline rules and the rules
  that can print a secret (`printenv`, `git config --get*/--list`,
  `git remote -v/get-url/show`), as optional extras to copy.
- Judge lists: `["$defaults", "<one example addition>"]` showing where a
  user's ownership facts and policy go.

### Docs and tests

- Rewrite the AGENTS.md "Core understands, config decides" invariant.
- Replace `docs/knowledge/core-generic-config-specific.md` with the new
  decision; amend `static-allow-is-a-speed-cache.md`; update the index.
- Update DESIGN.md, README.md and `skills/frisk/SKILL.md` wherever they say core
  ships no rules or describe `"$defaults"` in permissions.
- Update tests that assume no builtin allow, the old builtin text, or that the
  example carries every rule; shrink `testdata/eval-config.json` alongside the
  example.

### Eval

- `FRISK_EVAL_EXPECTED=1` limits `just eval-live` to fixtures that carry an
  `expect` (92 cases, about 50 judge calls).
- Run that subset and `just eval-git` (103 git fixtures) twice: under a
  builtins-only config in a scratch `XDG_CONFIG_HOME`, and under the
  maintainer's migrated config.

## Rollout

1. One `feat!` PR, `just check`, release note, `/polish`, maintainer review.
2. After the release is installed from brew, migrate the maintainer's
   `~/.config/frisk/config.json` to `"$defaults"` plus their facts, with a
   `.bak`. Not before: brew 0.3.0 would read `"$defaults"` as the old builtins.

## Not doing

- Content-hash rule ids: no consumer reads `ask_rule` ids; `reason` already
  carries the text.
- Builtins-first ordering regardless of marker position: diverges from autoMode
  and takes order control from the user.
- A switch to turn the baseline off: ask/deny rules override per verb.
