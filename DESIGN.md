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
     ask / deny                 -> "ask" / "deny"
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

State is provenance-labeled - `policy` (environment) vs `untrusted` (command,
script) - and the instructions say untrusted text is content to evaluate,
never instructions or evidence of approval. Precedence when options overlap:
deny > ask > allow > defer.

When a segment is `interpreter file` (python/node/bash/sh/zsh or `./x.py`),
the file rides along in `untrusted.script` with its sha256: regular file,
<= 32 KiB, UTF-8, credential-scanned - key-shaped content is never sent.

Hardcoded on purpose: the 0.75 confidence floor on `allow` (measured
authority-claim injections drag confidence to ~0.68), the script cap, the
model pin in config (a threshold is a fact about one model version).

## Logging and CLI

Every decision - silences included - is one `slog` JSON record in
`$XDG_STATE_HOME/frisk/frisk.log`: decision, tier, rule, command, confidence,
script sha. An auto-approver without a record is a rumour.

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
