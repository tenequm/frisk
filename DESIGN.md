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
3. permissions.allow: EVERY segment matches a rule
   and trips no screen (core ships no rules; bails on
    $(), backticks, (), heredocs, &, # comments, brace
    lists, variables the command does not set to a
    literal, and redirects other than 2>&1 and
    /dev/null; inside single quotes or escaped, all of
    these are text) -> "allow"
4. judge (needs jev.keyCmd): one Choice question
     allow + confidence >= 0.75 -> "allow"
     deny  + confidence >= 0.50 -> "deny" (below: "ask")
     ask   + confidence >= 0.50 -> "ask"  (below: silence)
     anything else              -> silence
     a decision missing from judge.decisions -> silence
  |
silence -> Claude Code native flow (rules -> classifier -> prompt)
```

## Config

`$XDG_CONFIG_HOME/frisk/config.json` - see [config.example.json](config.example.json).
Never read from the project directory, so a cloned repo cannot retarget the
gate. Missing file = no rules and the judge off, so every command passes
through; malformed file = silent for the session (logged).

Core understands commands and config decides about them. Core ships no allow
list: the static tier allows only what `permissions.allow` lists, and with no
rule a command passes through to the judge or to silence.
[config.example.json](config.example.json) carries a read-only starting list.
What core keeps is the parser and the screens - denied flags, risky arguments,
program text, credential paths and globs, hijacking environment variables.
A screen never decides anything: it only stops a rule such as `sed *` from
matching `sed -i`, a form the rule does not mean, and that command passes
through too.

A `gh api *` rule is kept to GET requests. gh sends a POST as soon as a field
(`-f`, `-F`, `--field`, `--raw-field`) or `--input` is given, so those, a
method other than `GET`, and the `graphql` endpoint pass through. gh runs a
`--jq` filter with the environment loaded, so on any gh command it is screened
like a jq program. A `ps *` rule does not cover a call that prints the
environment of other processes: `-E` on macOS, a BSD-style `e` as in `ps eww`
on Linux, or an `environ` column.

In the four `judge` lists `"$defaults"` splices the built-in prose,
autoMode-style. The `permissions` lists have no built-in entries, so there the
marker stands for nothing; it is accepted so that a config written for the
default allow list frisk once had still loads.

Rules use Claude Code's `Bash(...)` rule-content syntax, matched against
parsed segments - so `cd x && git push` still matches `git push *`. Trailing
`*` matches the rest; a standalone mid-pattern `*` matches one token.

### Git rule normalization

For a known git subcommand, matching reuses `describeGit` to remove global
options such as `-C` and `--no-pager`. Config overrides (`-c`, `--config-env`,
and attached `--exec-path`) and unknown subcommands keep literal matching.
Non-git matching and deny/ask/allow precedence are unchanged.

After the subcommand, a rule's flags are required in any position. Known
short/long spellings, short bundles and unambiguous long abbreviations match
together. Value-taking flags use the subcommand's `vals` table; their values
remain positional constraints, so `git commit -m *` also covers `--message=x`
and quiet commits. Other operands retain the usual wildcard semantics.
`--` ends flags and stays in the operand sequence. Unknown flags have literal
names; an unknown short bundle or missing value falls back to positional
matching for deny/ask and cannot allow through normalization.

Allow rules must name policy flags: force, deletion, hook skipping, amend,
upstream changes, hard reset and execution. Deny/ask match the force family
together; a lease-specific allow retains its lease constraint and cannot
authorize plain force. Force/delete refspecs also cannot
hide inside an ordinary push allow. With a flag-bearing allow rule, additional
flags must be named, except quiet, verbose and all. Rules without flags retain
positional matching after globals are removed, subject to these safety checks.
For example, `git commit --no-verify *` replaces flag-position and `-n`
variants; its trailing wildcard is needed to accept message operands.

An unquoted `#` that starts a word is a comment: the rest of the line is
dropped unread, so a quote inside it cannot hide the lines after it from the
rules. A command with a comment is never allowed statically, because a shell
that does not recognise comments would run that text.

What defeats static reasoning is decided where the shell would act on it, and
recorded on the statement it occurs in. A `<`, `>`, backtick or `$(` is a
construct only where the shell reads it as one: `rg "=>" src` and
`sed 's/<b>//g' f` are plain arguments, `echo "$(id)"` is not, because double
quotes do not stop a substitution. A verb that takes program text reads those
characters its own way, so its screen has to: awk's covers `>`, `>>`, `<` and
`@load` besides `system`, pipes and `ENVIRON`; sed's script walker covers `w`
and `e`; jq's module operators and yq's load operators read other files. Heredocs stay unsound
whoever reads them.

A statement that is only assignments (`S=/tmp/x; cat $S/f`) runs nothing and
needs no rule, but some other statement must match one. It is refused when the
value names a credential file or keeps an expansion, when the variable is
secret-named, and when the name is one that makes the shell or a later command
run or load something else: `PATH` and zsh's `path`, `HOME`, `BASH_ENV`,
`ZDOTDIR`, `PS4`, `NULLCMD`, `ARGV0`, loader and interpreter variables, any
`GIT_*`, anything shaped like `*_PAGER`, `*_EDITOR`, `*CONFIG*`, `*_OPTIONS` or
`*FLAGS`, proxies and trust roots, `CLAUDE_*`. The same names are refused as a
`NAME=value` prefix, and `printf -v` is screened as an assignment.

`judge.decisions` lists which of `allow`, `ask`, `deny` the judge may issue;
unset means all three. An empty list or any other value is a malformed config.

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
`git` and `redactions` vs `untrusted` (command, scripts) - and the
instructions say untrusted text is content to evaluate, never instructions or
evidence of approval. Precedence when options overlap: deny > ask > allow >
defer.

A secret-shaped literal on the command line does not leave the machine:
`untrusted.command` goes through the same `redactSecrets` as the log, and the
kinds found ride along as trusted `redactions` with one sentence of
instructions, so the judge still sees that a credential was inline. A
placeholder the judge sees only ever stands for part of one shell word. When a
redacted span held shell syntax - a private key block, a quoted password with
`;` or `&` - the command is not sent and the verdict is silence, like a
withheld script.

`git` is sent only for commands with a `git` or `gh` segment: `branch`,
`upstream`, `default_branch`, and `remote` reduced to host/owner/repo (never
userinfo), read in the directory the command runs in under one 200 ms
deadline. A field that cannot be read is omitted, never guessed.

`git.commands` adds one record per git segment, in order, five at most
(`git.commands_truncated` marks a longer command): the [description](#git) of
that segment plus what its repository says, read in the directory the segment
runs in (`-C`, or the directory a literal `cd` led to).

| field | when | value |
|-------|------|-------|
| `subcommand`, `class` | always | as described, or `unknown` |
| `forced`, `deletes_ref` | class `remote` and every push; otherwise only when true | boolean |
| `no_verify`, `amend`, `config_override` | only when true | `true` |
| `remote` | push | host/owner/repo of the push URL, or `unknown` |
| `destination` | push | the branch the arguments name; with no refspec the upstream branch, when the push goes to the upstream's remote; `HEAD` is the current branch; else `unknown` |
| `destination_is_default` | push | `yes`, `no`, or `unknown` when the remote has no `HEAD` ref locally |
| `uncommitted_files`, `untracked_files` | class `discard` | counts from one `git status --porcelain`, or `unknown` when it does not answer in time |
| `state` | always | `current`, or `unknown` when what this record reads from the repository may not hold when the segment runs |

`git checkout <word>` is the one class the repository settles: when the
directory resolves, the word is looked up. A local branch, or a branch on
exactly one remote, with no path of that name in the working tree makes it
`local`; a path and no such branch makes it `discard`; both or neither stays
`unknown`. What later segments lose follows the settled class, so
`git checkout main && git pull` reads `local`, `remote`.

`state` is `unknown` when the directory cannot be resolved or the command is
aimed at another repository (`--git-dir`, `GIT_DIR`, ...). State is not
followed across segments either, so an earlier git segment of the same command
can make it `unknown`, by what the record depends on:

- a push's fields depend on the remotes, and on the checked-out branch and
  its upstream when the push leaves its remote or destination to them (no
  remote, no refspec, or `HEAD`). An earlier `remote`, `clone` or `init` that
  is not a read, or any segment of class `exec` or `unknown`, may have changed a remote
  and invalidates every push after it. An earlier `switch`, `checkout`,
  `branch`, `worktree` or `bisect` that is not a read, a `-u` /
  `--set-upstream`, a `stash branch`, or a rebase given the branch to rebase
  may have moved the branch and invalidates only a push that goes by it:
  `git switch -c x && git push -u origin x` keeps its facts, `git switch main
  && git push` does not. `add`, `commit`, `merge`, `reset` and the like
  invalidate neither: `git add -A && git commit -m x && git push` keeps its
  facts.
- a discard's counts hold only while nothing but a `cd` or a git read has run
  before it. Any other earlier segment, git or not, and any redirect to a
  file may have written one: `touch n && git clean -fd` reports `unknown`,
  never zero.

The repository fields are then `unknown` and the ones read from the words
stay. A remote written as a URL is always read from the words. The record is
description only; the instructions
gain one sentence saying what it is, that it is trusted, that `unknown` means
frisk could not determine the field and that an absent optional field is
false. No allow or deny criterion in the builtin prose refers to it.

The lookups change nothing: git runs with `--no-optional-locks` and
`core.fsmonitor=false`, so reading a repository neither rewrites its index nor
starts a program its config names.

Every script the command runs rides along with its sha256: one as
`untrusted.script`, several as `untrusted.scripts`, 32 KiB combined. The probe
sees through wrappers (`time`, `timeout`, `env`, `nice`, `nohup`, `exec`,
`uv run`, `uvx`), versioned interpreters, interpreter flags, and shebangs on
directly executed files. A relative path resolves only against the hook cwd or
a literal `cd` earlier in the command - never a same-named file elsewhere.
A heredoc body is commands only when a shell reads it as its script from stdin
(`sh`, `bash`, `zsh`, `dash`, `ksh`, behind the same wrappers or `sudo` /
`doas`, with no script file and no `-c`): the statement it feeds, or a later
stage of that statement's pipeline, as in `cat <<EOF | bash`. An operand of
`-`, `/dev/stdin` or `/dev/fd/0` is stdin, not a script file, and `source` or
`.` reading one of those paths counts as that shell. Fed to anything
else it is text: the probe takes no script and no `cd` from it, while
`permissions.deny` and `permissions.ask` rules still match its lines.
`$NAME` and `${NAME}` resolve only for a variable the command itself assigns
exactly once, as its own statement, to a plain literal, before any control
flow and ahead of the use (`S=/tmp/x; cd "$S" && python3 run.py`); anything
less certain, and any command with a subshell, substitution, heredoc, `eval`,
`source`, `trap` or `alias`, stays `unresolvable`. Names the shell rewrites
itself (`PWD`, `OLDPWD`, `RANDOM`, `BASH*`, `ZSH*`, ...) never resolve, nor
does a bare `$NAME` followed by `:` or `[`, which zsh reads as a modifier or
subscript. A value of several words resolves for the probe only inside double
quotes, where bash and zsh both keep it one word (`S="/tmp/my dir"; python3
"$S/run.py"`).

The static tier and the `permissions.deny` / `permissions.ask` rules read the
same substitution, so every screen runs on the word the shell will see:
`A=-x; fd . "$A" rm` is screened as `fd . -x rm`, and a deny rule for
`gopass show *` matches `X=show; gopass $X k`. A word that keeps any expansion
after that - `$NAME`, `${...}`, a positional parameter, zsh's `$=NAME` - is
never allowed statically, because its value could be a flag, a credential path
or several words. `$?`, `$$`, `$#` and `$!` are numbers and pass.

A literal may be several words separated by spaces or tabs
(`C="git status"; $C --short`), with no quote or backslash among them. frisk
does not know which shell runs the command, and the two read such a value
differently in a word with no quotes: bash splits it into fields, with text
attached before or after joining the first or last field (`$A/x` with
`A="a b"` is `a` and `b/x`), while zsh keeps one word, spaces included. Inside
double quotes both keep one word; a word that mixes quoted and unquoted parts
(`$A"/x"`, `"$A"/x`) is not resolved. The static tier allows only when both
readings pass every screen and every segment of each that runs a command
matches an allow rule, so `A="log -p"; git $A` needs a rule for zsh's
`git "log -p"` too. In command position zsh looks up a program whose name has
spaces in it, finds none, and runs nothing; with a `/` in the word it runs that
path instead (`C="git -C /tmp/repo log"; $C` runs `./git -C /tmp/repo log` if
it exists), so such a command never settles, nor does a value of several words
in a word with a glob character. Deny and ask rules see both readings.

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

`judge.decisions` applies after the floors: an outcome it does not list becomes
silence, and Claude Code's own flow decides. With `["allow", "deny"]` the judge
never prompts: an `ask`, and a `deny` below its floor, are both withheld. The
reason and the log row keep what the judge concluded, with the decision logged
as `silent`: `jev ask (allow 0.30 / ask 0.62 / deny 0.08); ask withheld by
judge.decisions; closest rule: soft_deny "..." (0.71)`. It covers the judge
tier only: `permissions.deny` / `permissions.ask` rules, the static tier and the
file-tool guardrails are untouched.

Hardcoded on purpose: the 0.75 confidence floor on `allow` (measured
authority-claim injections drag confidence to ~0.68), the 0.50 floor under
`deny` (an uncertain deny costs one prompt, not a hard block), the 0.50 floor
under `ask` (every unwanted prompt in live traffic sat at 0.31-0.47 with allow
and ask nearly tied; below it Claude Code's own flow decides), the script cap,
the model pin in config (a threshold is a fact about one model version).

## Git

frisk reads a git invocation and describes it. It never decides one: no git
command is allowed, asked or denied by the core, and with no matching config
rule it reaches the judge like any other command.

`describeGit` takes one command segment and answers from its words alone:

- the subcommand, found behind git's own global options (`-C`, `-c`,
  `--git-dir`, `--work-tree`, `--no-pager`, `--bare`, ...). An option git
  would reject, or a first word that is not a plain name, leaves it `unknown`.
- a class, from a table of some fifty subcommands: `read`, `local` (changes
  refs, index or objects, which the reflog recovers), `discard` (can destroy
  uncommitted work), `remote` (talks to or changes a remote), `exec` (can run
  another program or reach credentials), and `unknown` for everything else.
  Where the arguments decide (`reset`, `checkout`, `restore`, `stash`,
  `branch`, `tag`, `config`, `worktree`, `clean`, ...) they are read, and
  `unknown` is the answer when they do not settle it: `git checkout main` may
  switch branches or overwrite a file named `main`, and only the repository
  can say which (see the record).
- flags, with short and long spellings as one: forced (`-f`, `--force`,
  `--force-with-lease`, a `+` refspec), deletes a ref (`-d`, `-D`, `--delete`,
  a `:dst` refspec, `--prune`, `--mirror`), `--no-verify` (`-n` on commit),
  `--hard`, `--amend`. Nothing after `--` is a flag, and a value such as the
  message after `-m` is never read as one.
- for `push`, the remote and the destination branch when the arguments are
  nothing, `<remote>`, `<remote> <branch>` or `<remote> <src>:<dst>`. `--all`,
  `--mirror`, `--tags`, several refspecs, a variable, or a flag outside a short
  known list make them `unknown`.

A `-c`, `--config-env` or `--exec-path=` option, or a variable such as
`GIT_SSH_COMMAND` or `GIT_CONFIG_*` set for the command, makes the class
`exec`: each swaps config or a program git runs. `--git-dir`, `--work-tree`,
`--namespace`, `--bare` and variables such as `GIT_DIR` mark the command as
aimed at a repository other than its directory's.

Left out on purpose: git's refspec and `push.default` rules, a flag screen for
every subcommand, aliases (an alias is an unknown subcommand, git config is
not read), and repository state across the segments of one command.

## Logging and CLI

Every decision - silences included - is one `slog` JSON record in
`$XDG_STATE_HOME/frisk/frisk.log`: decision, tier, rule, command, confidence,
probabilities, model, script sha, probe status, script count, closest-rule
answers, and for a judged git command `git`, its records as
`subcommand:class` joined by commas (`switch:local,push:remote`). An
auto-approver without a record is a rumour.

The log is plaintext and lives for weeks, so text that comes from tool input -
the command or file path, and a reason that quotes it - is redacted on the way
in. `redactSecrets` swaps provider tokens, private key blocks, `Authorization`
values, the values of secret-named flags, headers, assignments and JSON or YAML
fields, URL, `curl -u` and netrc passwords, hex longer than 40 characters and
high-entropy base64 for `[REDACTED:kind]`, and the record lists the kinds under
`redacted`. The decision is always computed on the raw command. A value that is
a variable, a substitution, a path, a number or one short word is not a secret
literal and stays, as does a 40-character git object id. The reason is redacted
where it is built, so `frisk check` and the permission prompt show the same text.

- `frisk hook` - the PreToolUse handler
- `frisk check '<command>'` - dry-run, prints decision + tier + reason
- `frisk validate [--live]` - config health check, see below

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
allow > silence; as for Bash, the only allows are the config's.

## Validate

A malformed config makes the hook stay silent for the whole session, so
`frisk validate` loads it with the hook's own loader and prints `error:`,
`warning:` and `info:` lines (exit 1 only on errors): parse failures, empty or
bad-glob rules, empty `Edit()` patterns, bare `*` in deny/ask, `$defaults` in
`permissions.allow` (a warning: it adds no rules), an allow list with no rules,
whether each judge list is unset, extends (`$defaults`) or replaces the builtins, the
effective `judge.decisions`, and whether `jev.keyCmd` runs - never printing any
part of the key. No network unless `--live`, which makes one real judge call
for `true`.

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
