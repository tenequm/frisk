---
name: frisk
description: Set up, diagnose and tune frisk, the PreToolUse permission gate for Claude Code Bash and file tools. Use when installing or configuring frisk, when a command is unexpectedly blocked, prompted or allowed, or to check whether frisk is working at all. Not for Claude Code's own permission settings.
---

# frisk

frisk is a Claude Code `PreToolUse` hook. Rules decide clear commands.
A [Jev](https://docs.typesafe.ai) judgment covers the gray zone. Everything
else is silence: the command falls through to Claude Code's own permission
flow. frisk shortcuts, never bypasses. A frisk allow still passes Claude
Code's deny/ask re-check. A frisk deny or ask holds in every mode, including
`bypassPermissions`. Every failure path is silence. Like Claude Code, core
ships a small read-only allow baseline and generic judge prose; config adds
the user's own rules and facts. Full detail:
[DESIGN.md](https://github.com/tenequm/frisk/blob/main/DESIGN.md).

## Set up

1. Write the config to `~/.config/frisk/config.json` (`$XDG_CONFIG_HOME/frisk/`).
   Start from
   [config.example.json](https://github.com/tenequm/frisk/blob/main/config.example.json)
   and trim its allow list: it holds optional extras on top of the builtin
   read-only rules. frisk never reads config from the project.
2. Register the hook in Claude Code settings. Use matcher
   `Bash|Edit|Write|NotebookEdit` to gate file edits too:

   ```json
   { "hooks": { "PreToolUse": [
     { "matcher": "Bash",
       "hooks": [{ "type": "command", "command": "frisk hook", "timeout": 10 }] }
   ] } }
   ```

3. Set `backend.apiKey`. It reads like a double-quoted shell string, so use a
   command that prints the key, for example
   `"$(gopass show -o api/typesafe)"`. `"${VAR}"` works too, but a
   repository's settings can set the session environment, so prefer a
   command. A literal key works but `validate` warns: the config is
   readable. Without a key, frisk runs rules-only and all unmatched commands
   fall through. `backend.endpoint`
   defaults to TypeSafe; OpenRouter is `https://openrouter.ai/api/v1/systemone`
   with model `jev-1.13` and an OpenRouter key. The old `jev` block still loads
   with a deprecation warning.
4. Run `frisk validate --live`. It checks the config and makes one real judge
   call. Exit 1 means errors.

## Diagnose

The log is the ground truth: `~/.local/state/frisk/frisk.log`
(`$XDG_STATE_HOME/frisk/`). Every decision writes one JSON line, silences
included.

- A command prompted, but the log has no line for it: the hook is not firing.
  Check the settings entry and that `frisk` is on Claude Code's PATH.
- A malformed config disables frisk silently for the whole session. Run
  `frisk validate` after every config edit.
- A prompt or deny whose reason names a rule or `judge` came from frisk. A plain
  Claude Code prompt means frisk stayed silent.
- `frisk check '<command>'` reproduces any decision and prints
  `decision tier reason`. Judge reasons include the probability split and the
  closest prose rule. A static reason ending in `(builtin)` names a builtin
  read-only rule, the one the last segment matched; an ask or deny rule
  overrides it. Tier `no-judge` means `backend.apiKey` is unset; reason
  `judge unavailable` means the key or the endpoint failed (the log line says
  which).
- To compare judge prose or models faithfully, add `--log-level debug` to the
  hook command for an evaluation period, then `frisk check --replay <file>` on
  `frisk.log` or an excerpt. A replay sends the state the judge first saw; a
  plain `frisk check` re-reads today's git and scripts and skews toward ask.
  Debug lines are large and hold command text and script bodies.

Not config problems: the judge confidence floors (allow needs >= 0.75, deny
and ask >= 0.50) and the guardrails that always ask (frisk's own config and
binary, `~/.claude/settings*.json`, `~/.claude/hooks`) are hardcoded.

## Tune rules (permissions.allow / deny / ask)

Rules use Claude Code `Bash(...)` syntax. frisk matches them per pipeline
segment, so `cd x && git push` matches `git push *`. A trailing `*` matches
the rest. A mid-pattern `*` matches one token. Static allow needs every
segment to match.

- Git rules are normalized: global options drop, flag spellings unify,
  `git commit -m *` covers `--message=x`. An allow rule must name policy
  flags: `git push *` never allows `--force`.
- `Edit(<pattern>)` rules gate Edit/Write/NotebookEdit and Bash redirect and
  `tee` targets. `~/` expands; a trailing `/**` means the subtree. A `>` or
  `tee` target needs one. On macOS, keep both `/tmp/**` and `/private/tmp/**`.
- Screens stop an allow rule from matching a form it does not mean (`sed *`
  vs `sed -i`). Substitutions, subshells, comments, heredocs, unresolved
  variables, hijacking env prefixes, unruled redirects, and risky verb flags
  all block static allow. The command then goes to the judge or to silence -
  a screen never decides. Run `frisk check`: the reason names what tripped.
- A `gh api *` rule covers plain GETs only. A field flag (`-f`, `-F`,
  `--field`, `--raw-field`), `--input`, a non-GET method, or the `graphql`
  endpoint passes through. That is the screen working, not a broken rule.
- Git aimed outside the working directory (`git -C /other`, `cd /other && git`,
  `--git-dir`) and recursive reads of `~`, a directory above it, or a hidden
  directory in it (`rg x ~`, `grep -r x ~/.config`) never settle statically:
  git runs programs a foreign repository's config names, and credential files
  hide under such directories. They go to the judge or fall through.

## Tune the judge (judge.*)

`"$defaults"` splices the builtin prose into a list, in place; a list without
it replaces the builtins. The builtin prose claims no ownership, so add which
repositories, hosts and directories are the user's to `environment`.
`soft_deny` maps to ask, `hard_deny` to deny. `judge.decisions` limits what the judge may issue:
`["allow", "deny"]` means it never prompts. Withheld verdicts log as `silent`.

Measured findings:

- The judge reads prose literally. Name routine work in allow: project
  writes, build and test tools with their caches, manifest-recorded installs,
  local git, personal-branch pushes. Otherwise it prompts on commits at 0.95+
  confidence.
- State environment facts: which hosts and directories are the user's own,
  which branches are shared.
- Keep the lists non-overlapping. A command that half-fits two lists scores
  low confidence on both.
- Write secrets prose against destinations, not acts. Forbid exposure
  (printed, left in a file) and named outside destinations (paste sites,
  webhooks, issues, gists). Name what is allowed: the provider's API, the
  user's hosts, consuming CLIs. "Reading a secret store" denies routine
  piping between the user's own stores.

Tuning loop: find repeated asks in the log, add a static rule or name the
work in allow prose, run `frisk validate`, then `frisk check` the exact
commands.
