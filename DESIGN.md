# frisk

A quick pat-down for every command your agent runs.
The clean ones walk through. The rest wait for you.

A Claude Code `PreToolUse` hook for Bash: one Go file, stdlib only.
Deterministic rules decide first, a [Jev](https://docs.typesafe.ai) judgment
covers the gray zone, everything else is silence - which lands exactly where
it lands today: Claude Code's own rules, then the auto-mode classifier, then you.

frisk is a shortcut, never a bypass:

- A frisk `allow` still passes Claude Code's `permissions.deny`/`ask` re-check.
- A frisk `deny`/`ask` is honored in every mode, including `bypassPermissions`.
- Every failure path (bad config, no key, Jev timeout, malformed answer,
  low confidence) is silence.

## Decision flow

```
stdin: PreToolUse JSON (Bash only; anything else -> exit 0)
  |
parse into pipeline segments (|, &&, ||, ;, newline)
  |
1. permissions.deny  match -> "deny"
2. permissions.ask   match -> "ask"
3. static allow: EVERY segment provably read-only
   (builtin verb table + config allow; bails on
    $(), backticks, redirects, heredocs, &)     -> "allow"
4. judge (needs jev.keyCmd): one Choice question
     allow + confidence >= 0.75 -> "allow"
     deny  + confidence >= 0.50 -> "deny" (below: "ask")
     ask   + confidence >= 0.50 -> "ask"  (below: silence)
     anything else              -> silence
  |
silence -> Claude Code native flow (rules -> classifier -> prompt)
```

## Config

`$XDG_CONFIG_HOME/frisk/config.json` - see [config.example.json](config.example.json).
Never read from the project directory, so a cloned repo cannot retarget the
gate. Missing file = defaults with the judge off; malformed file = silent for
the session (logged). `"$defaults"` splices the built-in entries, autoMode-style.

Rules use Claude Code's `Bash(...)` rule-content syntax, matched against
parsed segments - so `cd x && git push` still matches `git push *`. Trailing
`*` matches the rest; a standalone mid-pattern `*` matches one token.

## The judge

One Choice question per judged command, mapped straight onto
`permissionDecision`:

| option  | criteria                                        |
|---------|-------------------------------------------------|
| `allow` | `judge.allow` prose                             |
| `ask`   | `judge.soft_deny` prose (the prompt IS the intent check) |
| `deny`  | `judge.hard_deny` prose                         |
| `defer` | none of the above clearly applies -> silence    |

State is provenance-labeled - trusted `policy` (environment), `cwd`, `probe`,
and `git` vs `untrusted` (command, scripts) - and the instructions say
untrusted text is content to evaluate, never instructions or evidence of
approval. Precedence when options overlap: deny > ask > allow > defer.

`git` is sent only for commands with a `git` or `gh` segment: `branch`,
`upstream`, `default_branch`, and `remote` reduced to host/owner/repo (never
userinfo), read in the directory the command runs in under one 200 ms
deadline. A field that cannot be read is omitted, never guessed.

Every script the command runs rides along with its sha256: one as
`untrusted.script`, several as `untrusted.scripts`, 32 KiB combined. The probe
sees through wrappers (`time`, `timeout`, `env`, `nice`, `nohup`, `exec`,
`uv run`, `uvx`), versioned interpreters, interpreter flags, and shebangs on
directly executed files. A relative path resolves only against the hook cwd or
a literal `cd` earlier in the command - never a same-named file elsewhere.

`probe.status` tells the judge why a body is absent: `attached`, `missing`,
`unresolvable`, `oversize`, `non-utf8`, `multiple-truncated`. A script whose
resolved path or content looks credential-bearing (`withheld-credential-shaped`)
is never sent and the verdict is silence.

The reason shown in the prompt, `frisk check`, and the log is one line: the
probability split, then the closest rule, then any script that was expected
but not attached - `jev ask (allow 0.30 / ask 0.62 / deny 0.08); closest rule:
soft_deny "..." (0.71); script build.py not attached: unresolvable after cd`.
The closest rule comes from two more Choice questions in the same request
(`ask_rule`, `deny_rule`: one option per prose item plus `none`). It is a
separate answer that can disagree with the verdict, so it only annotates the
reason and never changes the decision.

Hardcoded on purpose: the 0.75 confidence floor on `allow` (measured
authority-claim injections drag confidence to ~0.68), the 0.50 floor under
`deny` (an uncertain deny costs one prompt, not a hard block), the 0.50 floor
under `ask` (every unwanted prompt in live traffic sat at 0.31-0.47 with allow
and ask nearly tied; below it Claude Code's own flow decides), the script cap,
the model pin in config (a threshold is a fact about one model version).

## Logging and CLI

Every decision - silences included - is one `slog` JSON record in
`$XDG_STATE_HOME/frisk/frisk.log`: decision, tier, rule, command, confidence,
probabilities, model, script sha, probe status, script count, closest-rule
answers. An auto-approver without a record is a rumour.

- `frisk hook` - the PreToolUse handler
- `frisk check '<command>'` - dry-run, prints decision + tier + reason

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "frisk hook", "timeout": 10 }] }
    ]
  }
}
```

Uninstall = remove the hook entry.

## File tools

`Edit`, `Write` and `NotebookEdit` are gated by deterministic path checks only,
no judge. `Edit(<path-pattern>)` rules in `permissions.deny/ask/allow` apply to
all three; bare rules stay Bash-only and `Edit(...)` rules never match a Bash
segment. Patterns: `~/` expands to home, a trailing `/**` is the directory and
everything under it, otherwise `filepath.Match` on the cleaned absolute path.
Builtin guardrail paths (frisk's own config dir, the frisk binary,
`~/.claude/settings*.json`, `~/.claude/hooks`) ask, checked raw and
symlink-resolved. Precedence: config deny > config ask > guardrail ask > config
allow > silence; there are no builtin allows for file tools.

## Provenance

Distilled from [jevgate](https://github.com/thevibeworks/jevgate) (code-first
tiers, allow-or-silence, decisions log), [Letta jev-auto](https://github.com/letta-ai/mods)
(single Choice, no threshold soup), [Jevvy](https://github.com/PanAchy/jevvy)
(global-only config), [construct-auto-classifier](https://github.com/godspede/construct-auto-classifier)
(judge script contents), and the Claude Code
[hooks](https://code.claude.com/docs/en/hooks) /
[permissions](https://code.claude.com/docs/en/permissions) /
[auto mode](https://code.claude.com/docs/en/auto-mode-config) docs.

Open assumption to verify on first live call: the `Authorization: Bearer`
header shape against the TypeSafe API reference.
