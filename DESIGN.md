# frisk

A quick pat-down for every command your agent runs.
The clean ones walk through. The rest wait for you.

A Claude Code `PreToolUse` hook for Bash, stdlib only.
Deterministic rules decide first, a [Jev](https://docs.typesafe.ai) judgment
covers the gray zone, everything else is silence - which lands exactly where
it lands today: Claude Code's own rules, then the auto-mode classifier, then you.

frisk is a shortcut, never a bypass:

- A frisk `allow` still passes Claude Code's `permissions.deny`/`ask` re-check.
- A frisk `deny`/`ask` is honored in every mode, including `bypassPermissions`.
- Every failure path (bad config, no key, judge timeout, malformed answer,
  low confidence) is silence.

## Decision flow

```
stdin: PreToolUse JSON (Bash only; anything else -> exit 0)
  |
parse into pipeline segments (|, &&, ||, ;, newline)
  |
1. permissions.deny  match -> "deny"
2. permissions.ask   match -> "ask"
3. allow: EVERY segment matches a permissions.allow
   or builtin read-only rule and trips no screen
   (bails on $(), backticks, (), heredocs other than a literal
    one no program runs, &, # comments, brace
    lists, variables the command does not set to a
    literal or that are not $HOME or $TMPDIR, and
    redirects other than stream merges, /dev/null,
    screened stdin files or literal writes covered by
    Edit rules; inside single quotes or escaped, all of
    these are text) -> "allow"
4. judge (needs backend.apiKey): one Choice question
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
gate. Missing file = only the builtin read-only rules and the judge off, so
every other command passes through; malformed file = silent for the session
(logged).

Core ships what is right for any unix user, like Claude Code: a built-in set
of read-only rules (`builtinAllow`) and generic judge prose (`builtinJudge`).
The builtin rules are the read-only verbs that settle real traffic; they always
apply, `permissions.ask` and `permissions.deny` override them, and a static
reason ends in `(builtin)` when the rule it names is builtin. The reason names
the last segment's rule, so `just check && ls` reads `ls * (builtin)` though
`just check` needed the config's rule. Anything else settles only
through `permissions.allow`, and with no rule a command passes through to the
judge or to silence. [config.example.json](config.example.json) carries
optional read-only extras and temporary-file write scopes.
What core keeps is the parser and the screens - denied flags, risky arguments,
program text, credential paths and globs, hijacking environment variables,
a git command aimed outside the working directory (`-C`, a `cd`, `--git-dir`,
`--work-tree`: git runs programs a repository's config names), and a recursive
read (`rg`, `grep -r` or `-d recurse`, `diff -r`, `git diff`, which turns
no-index by itself for a path outside the repository) of the home directory, a
directory above it, or a hidden directory in it, where credential files sit
under names no word shows. rg and grep walk "." with no path given, so they do
not settle statically from such a directory either. A `cd` is followed only to
one literal target: zsh's `cd old new` and `cd +1`, and any relative target
while `CDPATH` is set, leave the directory unknown. `sed -l` takes a value in
GNU sed and none in BSD sed, so a command carrying it never settles statically.
Shell history files count as credential files.
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

In the four `judge` lists `"$defaults"` splices the built-in prose in place,
autoMode-style; a list without it replaces the builtins. The builtin prose
claims no ownership: which repositories, hosts and organizations are the
user's comes only from config, and without those facts the items that depend
on them stay silent rather than allow. In the `permissions` lists the marker
stands for nothing, since the builtin rules apply whatever the list says.

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
and `e`; jq's module operators and yq's load operators read other files. A heredoc
stays unsound unless its body is literal and no program it feeds runs stdin
(see the probe section below).

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
`git`, `data` and `redactions` vs `untrusted` (command, scripts) - and the
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
| `forced`, `deletes_ref` | class `remote` and every push; otherwise only when true, and never on a branch or tag deletion | boolean |
| `deleted_refs` | a branch or tag deletion | one entry per ref: `ref` (full refname); `unique_commits`, the commits no other ref holds with the refs deleted alongside excluded, or `unknown` (out of time, or past the first five refs) - one `rev-list --count` over all of them settles the usual 0, and only a non-zero total is counted per ref; `tip_fetched` when the ref's newest reflog entry is a fetch |
| `loses_commits` | a branch or tag deletion | `true` when any deleted ref holds commits no other ref does, `false` only when every `unique_commits` is a current 0, else `unknown`; it counts reachable commits, not reflog history, and `tip_fetched` plays no part, since a reflog subject proves no remote still holds the commits |
| `no_verify`, `amend`, `config_override` | only when true | `true` |
| `remote` | push | host/owner/repo of the push URL, or `unknown` |
| `destination` | push | the branch the arguments name; with no refspec the upstream branch, when the push goes to the upstream's remote; `HEAD` is the current branch; else `unknown` |
| `destination_is_default` | push | `yes`, `no`, or `unknown` when the remote has no `HEAD` ref locally |
| `uncommitted_files`, `untracked_files` | class `discard` | counts from one `git status --porcelain`, or `unknown` when it does not answer in time |
| `ignored_files` | class `discard`, a `clean` with `-x` or `-X` | ignored entries counted by the same call, run with `--ignored=matching`, an ignored directory once as an untracked one is; `-x` deletes them along with untracked files and `-X` only them |
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
  never zero. A deletion's `deleted_refs` follow the same rule, since such a
  segment may also have moved a ref.

The repository fields are then `unknown` and the ones read from the words
stay. A remote written as a URL is always read from the words. A dry run
(`clean -n`) is class `read` and carries no counts. The record is
description only; the instructions
gain one sentence saying what it is, that it is trusted, that `unknown` means
frisk could not determine the field and that an absent optional field is
false. The builtin prose decides git commands from these records.

The lookups change nothing: git runs with `--no-optional-locks` and
`core.fsmonitor=false`, so reading a repository neither rewrites its index nor
starts a program its config names.

`gh.commands` does the same for gh, five at most (`gh.commands_truncated`
marks a longer command), built in the same walk and under the same deadline
(`gh.go`). It is read offline - no network call, so no pull request's base
branch or author - and the words are split the way gh's flag parser splits
them: short flags unbundled, and a value flag taking the rest of its word or
the next one, from a per-command list that is complete where a value hides
what the record reads.

| field | when | value |
|-------|------|-------|
| `subcommand`, `class` | always | `pr checks`, `api`, ...; a class from the table, or `unknown` for an alias, an extension or a missing pair |
| `repo` | a command on one repository, or one whose words name it | host/owner/repo from the last `-R`/`--repo` (over a `GH_REPO=` prefix), a URL or, for `repo` commands, an `OWNER/REPO` right after the subcommand, an `api` endpoint under `repos/`, or the checkout: the remote `gh repo set-default` marked (`base`, or `OWNER/REPO` on that remote's host; upstream, github, origin first, as gh orders them), else the only remote. `--hostname` or a `GH_HOST=` prefix sets the host of an `OWNER/REPO`. Every source must agree: a URL or repository elsewhere in the words also counts the checkout, since a flag frisk reads as taking no value may have hidden a selector. `unknown` on any disagreement, when gh would have to choose a remote, or once an earlier segment may have changed the remotes, the gh default, `GH_REPO` or `GH_HOST`. A `GH_REPO` or `GH_HOST` already exported in the session is not visible |

The classes reuse git's where the meaning carries over and add two:

| class | gh commands |
|-------|-------------|
| `read` | `pr view/list/checks/diff/status`, `issue view/list/status`, `run view/list/watch`, `release view/list`, `repo view/list`, `workflow view/list`, `search`, `status`, `browse`, list and get commands, `api` with a GET or an inline GraphQL query without `mutation` (a query from a file, stdin or a variable is `unknown`) |
| `local` | `pr checkout`, `run download`, `release download`, `repo clone`, `repo set-default`, `config set` of a key that names no program |
| `collaborate` | pull requests, issues and comments: create, edit, comment, review, ready, close, reopen; `run rerun/cancel` |
| `merge` | `pr merge`, and `pr review` with `-a`/`--approve`, bundled or not |
| `remote` | every other change on GitHub: releases, repository settings, labels, secrets, variables, `workflow run`, `pr close --delete-branch`, `api` writes |
| `exec` | `auth` changes, `auth token` and `auth status --show-token`, extensions, aliases, `config set` of `editor`, `pager` or `browser`, and a `--jq` filter that reads the environment |

The builtin prose decides gh commands from these records: `read` and `local`
anywhere, `collaborate` on any repository, `merge` on the user's own; `merge`
and `remote` elsewhere ask.

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
Its terminator is the delimiter after the quote removal bash and zsh share, so
a backslash inside single quotes stays, as in `<<'a\b'`.
The static tier lets a heredoc through only when its delimiter is one quoted
word, `'EOF'`, `"EOF"` or `\EOF` made of letters, digits, `_`, `.` and `-`, so
nothing in the body expands and no shell reads its end elsewhere; and when no
statement it feeds, down the whole pipeline and past a trailing `|`, may run
stdin as code: a shell, `python` or `node`, `source` or `.`, any `sudo` or
`doas` command, a wrapper that hides its command, or no command at all, as in
`exec <<EOF`, which feeds the statements after it. The body is then input like
an operand the owner's allow rule already covers, and runs nothing. A command
with heredoc text and a loop stays unsound: a body line reading `done` could
end the loop early.
`$HOME`, `${HOME}`, `$TMPDIR` and `${TMPDIR}` resolve from the hook process
(home via `os.UserHomeDir`, TMPDIR via its environment), including in literal
assignments. Empty values or values containing whitespace, glob characters,
quotes, backslashes or `$` stay unresolved. Any write to HOME or TMPDIR, or
to the existing expansion variables, disables all resolution. The probe uses
the same substitution, with the additions below. Other `$NAME` and `${NAME}` references resolve only
for a variable the command itself assigns
exactly once, as its own statement, to a plain literal, before any control
flow and ahead of the use (`S=/tmp/x; cd "$S" && python3 run.py`); anything
less certain, and any command with a subshell, substitution, heredoc, `eval`,
`source`, `trap` or `alias`, stays `unresolvable`. Names the shell rewrites
itself (`PWD`, `OLDPWD`, `RANDOM`, `BASH*`, `ZSH*`, ...) never resolve, nor
does a bare `$NAME` followed by `:` or `[`, which zsh reads as a modifier or
subscript. A value of several words resolves for the probe only inside double
quotes, where bash and zsh both keep it one word (`S="/tmp/my dir"; python3
"$S/run.py"`).

The probe, which only reads, goes further than the static tier. A subshell,
substitution or heredoc cannot assign in the shell that runs the command, so
an assignment ahead of the first one still holds after it
(`S=/tmp/x; N=$(date); python3 $S/run.py`); an assignment at or after the
first parenthesis, substitution or backtick is never taken, since it may sit
inside one. And a value may use a variable resolved before it
(`R=/tmp; S=$R/x`), unless a `~` comes first, which bash expands before the
variable (`S=~$R`). Past a substitution the tokenizer may read quotes apart
from the shell, and builtins write names in forms no word shows (`printf -vS`,
`read {S,T}`, `$[S=1]`), so the probe also reads the raw command: a name
resolves only when the text names it nowhere but in its one assignment and in
plain reads (`$S`, `${S}`, `${S:-x}`), heredoc bodies included. HOME and
TMPDIR resolve only when the text never names them that way. Code that may
assign where no word shows it - arithmetic (`((`, `$((`, `$[`), a `(` inside a
word, a zsh glob qualifier that can run code, `command .` or `builtin .` -
leaves the whole command unresolved, and so does an assignment in an and-or
list run in the background. A shell reading a literal heredoc body expands it
itself, in an environment this command does not settle (`env -i`, `sudo -H`),
so nothing resolves there.

A file the command writes with a redirect before running it is not read from
disk, which does not hold what will run yet. When the write is `cat > file`
fed a literal heredoc, ahead of any control flow, not piped or backgrounded,
not after `||` and not under a noclobber the command sets, the body is the
script: it is attached under the file's path, with secret-shaped spans
redacted as in the command and the digest taken of what is sent, assuming as
for a `cd` that the statements before it succeed and that the write does (a
noclobber set outside the command, or a read-only file, keeps the old one).
Only `chmod`, a `cd` and other such `cat` writes to resolvable paths may come
between the write and the run: any other program may change the file by means
no redirect shows (`cp`, `tee`, a script it runs), and so may a write to a
path that differs only in case. Any other redirect to the file (`>>`, an
expanding or `<<-` heredoc, another program's output, a write inside an
`if`), or anything else between, leaves the script `unresolvable`, noted as
written earlier in the command.

A file redirected into a shell or interpreter that reads its program from
stdin (`bash < x.sh`, `sh -s < x.sh`, `python3 - < x.py`) is the script, read
like a file operand, or taken from the heredoc that wrote it. A second stdin
redirect beside it, a here-string or a `<&` dup among them, leaves it
`unresolvable`.

ssh runs the words after the destination as a command on that host, so the
probe reads them as one. Its options are read on both sides of the
destination; `-N`, `-s`, `-W`, `-O`, `-G`, `-Q`, `-V`, `-F`, or a
`RemoteCommand`, `SessionType`, `StdinNull` or `ForkAfterAuthentication`
option, however ssh would split it, leave the segment unread. An unquoted `~`
in the remote words is this machine's home, which the local shell puts there.
When the remote command is a shell or interpreter reading stdin, as above, or
is absent, which starts a login shell that reads it, what ssh is fed is the
script: a literal heredoc is attached like a written one, redacted, its digest
taken of what is sent, under the path `<<DELIM`; a local file given with `<`
is read like a script operand. Only the first remote statement that reads
stdin gets it, and `-n` or `-f` feeds nothing. It is `unresolvable` when a
remote statement other than `cd` or `chmod` runs first and may read it, when
ssh's stdin is fed more than one way, and for an expanding or `<<-` heredoc,
as for a written script.

A script the remote command runs from a path on the host (`bash ~/deploy.sh`,
`./x.sh`, a remote `bash -s < /srv/x.sh`) cannot be read, and is reported
`remote-only` - unless the last `scp` or `rsync` before it copied a
resolvable local file to that destination and path, which is then attached as
it stood when copied. The destination must match as written, user included,
and neither ssh nor the copy may pass an option that can route it elsewhere
(ssh `-J`, `-l`, `-o`, `-p`, `-S`; scp `-D`, `-F`, `-J`, `-o`, `-P`, `-S`;
rsync `-e`). Remote paths are compared as written, `~` standing for the
host's home, with no `..` or shell syntax, and a literal remote `cd` is
followed only when what comes after it needs it to succeed (`&&`). A bare
name runs from the host's `PATH` and is never matched. A copy counts only
while each statement after it is joined by `&&` and nothing but `cd`, `chmod`
or an ssh that changes nothing there runs between, here or on any host, as
for a written script. A copy of a directory, a symlink by rsync, or two files
to one path counts for nothing, and an rsync only with `-c` or `-I`, since its
size-and-time check may skip a file, and only with options that neither skip
files nor move them (`-avzqhPcIrlptgoDE`, `--chmod=` and long forms such as
`--archive`). Every script that runs on a host carries it as `host`
(`script_host` when it is the only one): the destination as the command names
it, without user or port, never from config. A remote command with control
flow, a substitution or a heredoc of its own, stdin fed through a pipe, and a
remote `sudo bash x.sh` stay as they were: no script and no status.

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

`data` lists, in order, text inside the command that the shell does not run
where it stands, so the judge stops reading a test string, a commit message or a brief as an
action. Each record names the `program` and `via`, which locates the text in
`untrusted.command` without copying it:

| via | when | fields |
|-----|------|--------|
| `heredoc` | a literal heredoc fed to `cat` whose output is redirected to a file, not piped on or backgrounded, and whose file name no other statement contains; or to `git commit` / `git tag` with `-F -` | `delimiter`, and for `cat` the `file` as written and `appends` for `>>`, both redacted like the command |
| `flag` | a message flag of `git commit`, `tag` or `stash` (`-m`, `--message`, bundled or attached), or a title, body, notes, subject or comment flag of `gh pr`, `gh issue` or `gh release` (create, edit, comment, review, merge, close) | `flag` as written |
| `operand` | `frisk check` without `--replay` | none |

The program must be named bare (`git`, not `./git`), so it is the one on
`PATH` and not a file the command may have written.

Flags and operands count only in the command's own statements ahead of the
first parenthesis, substitution or backtick: a value could hold a
substitution that runs, and past one the tokenizer may read quotes apart from
the shell. A word holding `${` or `$~` leaves its statement out too, since
zsh's `${(e)X}` and `$~X` and bash's `${X@P}` run what a value holds. A
heredoc the shell expands, or fed to a shell, an interpreter, `ssh` or any
other program that may run it, gets no record, and neither does a file another
statement names (`sh < f`, `source f`, `$(cat f)`). A file nothing in the
command names may still run later, read by a git hook, `make` or a shell at
startup, and the instruction says so. Like `git.commands` it is description only, with one sentence of
instructions, and the builtin environment prose says listed text is content.

`probe.status` tells the judge why a body is absent: `attached`, `missing`,
`unresolvable`, `oversize`, `non-utf8`, `multiple-truncated`, `remote-only`.
A script whose resolved path or content looks credential-bearing
(`withheld-credential-shaped`) is never sent and the verdict is silence.

The reason shown in the prompt, `frisk check`, and the log is one line: the
probability split, then the closest rule, then any script that was expected
but not attached - `judge ask (allow 0.30 / ask 0.62 / deny 0.08); closest rule:
soft_deny "..." (0.71); script build.py not attached: unresolvable after cd`.
The closest rule comes from two more Choice questions in the same request
(`ask_rule`, `deny_rule`: one option per prose item plus `none`). It is a
separate answer that can disagree with the verdict, so it only annotates the
reason and never changes the decision.

`judge.decisions` applies after the floors: an outcome it does not list becomes
silence, and Claude Code's own flow decides. With `["allow", "deny"]` the judge
never prompts: an `ask`, and a `deny` below its floor, are both withheld. The
reason and the log row keep what the judge concluded, with the decision logged
as `silent`: `judge ask (allow 0.30 / ask 0.62 / deny 0.08); ask withheld by
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
fields (a name is secret when it ends in a secret word, like `API_KEY` or
`authToken`, or in one and a short qualifier, like `TOKEN_RO` or `KEY_BASE`,
not when one sits inside it, like `session_id`, `author` or `max_tokens`), URL, `curl -u` and netrc passwords, hex longer than 40 characters and
high-entropy base64 for `[REDACTED:kind]`, and the record lists the kinds under
`redacted`. The decision is always computed on the raw command. A value that is
a variable, a substitution, a path, a number or one short word is not a secret
literal and stays, as does a 40-character git object id. The reason is redacted
where it is built, so `frisk check` and the permission prompt show the same text.

- `frisk hook` - the PreToolUse handler
- `frisk check [flags] '<command>'` - dry-run, prints decision + tier + reason
- `frisk check [flags] --replay <log-file>` - judge logged requests again, see below
- `frisk validate [--live] [flags]` - config health check, see below

Flags go before the command: `frisk check ls --log-level debug` judges
`ls --log-level debug`. A flag placed before `hook` makes the hook silent, never
a usage error, since exit 2 would block every tool call.

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

## Debug log and replay

The log keeps the command and the verdict, not what the judge was shown. A
replay through `frisk check` rebuilds the trusted state from the replaying
machine: today's branch and remotes, and a probe that finds most scripts gone,
so its verdicts skew toward ask
([finding](docs/knowledge/replays-are-skewed-by-trusted-state.md)).

`--log-level debug` on `hook` or `check` adds two fields to the verdict line of
every answered judge call: `request`, the body as sent (already redacted and
screened, embedded as an object), and `answers`, the parsed answers with the
response's model and usage. The key rides only in a header and is never
logged. The level is a command-line option only - no config key, nothing from
the environment - because a debug line holds command text and script bodies.
Lines run roughly 5-12 KB each, so debug is for evaluation periods; the log is
already `0600`.

`frisk check --replay <file>` (`-` for stdin) reads JSONL such as `frisk.log`
or an excerpt and, for every line with a `request`, sends its `state` as logged
except the `policy`, which like the questions is built from the current `judge`
prose, then applies the same floors and `judge.decisions` as a live call. The
key is resolved once for the whole run, and one that does not resolve exits 1. It prints one `decision tier
reason` line per replayed record in input order, then `replayed N, skipped M`;
lines without a request state, malformed ones included, are skipped. With
`--log-level debug` each replay is logged with its own request, so two configs
or models can be compared on the same inputs. An unreadable file exits 1 with
`silent replay-error`. The reason carries no "script not attached" note: that
comes from the probe, which a replay skips.

## File tools

`Edit`, `Write` and `NotebookEdit` are gated by deterministic path checks only,
no judge. `Edit(<path-pattern>)` rules in `permissions.deny/ask/allow` apply to
all three; bare rules stay Bash-only and `Edit(...)` rules never match a Bash
segment. Patterns: `~/` expands to home, a trailing `/**` is the directory and
everything under it, otherwise `filepath.Match` on the cleaned absolute path.
Builtin guardrail paths (frisk's own config dir, the frisk binary,
`~/.claude/settings*.json`, `~/.claude/hooks`) ask, checked raw and
symlink-resolved. Precedence: config deny > config ask > guardrail ask > config
allow > silence; the builtin rules are Bash-only, so here the only allows are
the config's.

## Validate

A malformed config makes the hook stay silent for the whole session, so
`frisk validate` loads it with the hook's own loader and prints `error:`,
`warning:` and `info:` lines (exit 1 only on errors): parse failures, empty or
bad-glob rules, empty `Edit()` patterns, bare `*` in deny/ask, `$defaults` in
`permissions.allow` (a warning: it adds no rules), how many builtin read-only
rules apply, whether each judge list is unset, extends (`$defaults`) or
replaces the builtins, the
effective `judge.decisions`, each `backend` value with where it came from
(flag, file or default), and whether `backend.apiKey` resolves - never printing
any part of the key. No network unless `--live`, which makes one real judge
call for `true`.

## Backend

`judge` holds policy (what may be decided); `backend` holds the connection
(where the question goes). The request is TypeSafe's System One shape, which
TypeSafe (`https://api.typesafe.ai/v1/systemone`, the default) and OpenRouter
(`https://openrouter.ai/api/v1/systemone`, or the alpha
`https://openrouter.ai/api/alpha/decisions`) both serve, so switching vendor or
model is `backend.endpoint` and `backend.model`. The confidence floors were
measured on Jev, so a different model needs its own replay before it decides.

`backend.apiKey` is read as the inside of a double-quoted shell string: a
literal, `${VAR}` or `$(command)`. A value with no `$` or backtick is used as
is; otherwise `sh` evaluates it, in its own process group so a timeout kills
the key command too, with the expression passed in the environment rather than
the `-c` text so the key it yields stays off argv. `validate` warns on a literal
key, since the config is readable by anything that reads files. Prefer
`$(command)` to `${VAR}`: a repository's `.claude/settings.json` can set the
session's environment, so it could swap in its own key and read your commands
in that vendor's request logs. `endpoint` must be https, or http on a loopback
host, and the judge never follows a redirect, because the key travels as a
bearer token.

The scalar options (`backend.*`, `judge.decisions`) also take flags on `hook`,
`check` and `validate`, named as in the file (`--backend.model=...`,
`'--backend.apiKey=$(...)'`), which override it. The key flag refuses a literal,
which would sit in argv. No option is read from the environment: a
repository's `.claude/settings.json` can set the session's environment, but not
the user's hook command. `XDG_CONFIG_HOME` still chooses where the config file
is read from, as it always has.

The older `jev` block still loads as an alias: `jev.keyCmd` becomes
`apiKey: "$(<argv, quoted>)"`, `validate` warns, and setting the same option in
both blocks is an error.

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

## Static loops and redirected writes

The static tier screens and matches every body statement of a literal `for`
loop for each list value, at most 20. The loop variable resolves only inside
that body and must have no other writer, and it may not be `IFS`, `HOME` or
`CDPATH`. Every unrolled statement is read both ways, bash's and zsh's, like
any other; a list word holding an unquoted value of several words stays
unsound, since bash loops once per field and zsh once over the whole value.
Nested loops and loops that change working directory stay unsound. `while` and `until` conditions and bodies use
ordinary command rules; polling loops need no termination proof. Structural
`do`, `done`, `then`, `fi` and `else` words run nothing themselves.

Output redirects (`>`, `>>`, `2>`, `&>`) and `tee` or `tee -a` file operands
need an `Edit(<pattern>)` allow rule matching their cleaned absolute target.
Relative paths need a known cwd, following literal `cd` statements joined
with `&&`. A `cd` inside control flow stays unsound. Targets containing a
`..` component are refused before cleaning, `~/` expanding without cleaning,
and a `~` left quoted is refused. A redirect ahead of the verb, and one on a
command word zsh cannot find, stay unsound. Credential
paths, `.env*` components, `.githooks`, and every path Claude Code never
auto-approves a write to (`.git`, `.claude`, `.vscode`, `.cargo`, shell rc
files, `.gitconfig`, `lefthook.yml`, `.mcp.json` and the rest of its protected
list) never qualify, so a redirect cannot settle a write an Edit under the
same rule would not. Target and ancestor symlinks, nonregular targets and shell network pseudo-paths
are refused. On macOS, the system `/tmp`
alias is checked as `/private/tmp`; the example config includes both scopes.
An input redirect (`< file`, `0< file`) is screened like an operand naming the
file: a literal path that is no credential file or network pseudo-path, also
once joined to a literal `cd`, fed to a program that does not run stdin as code
(the same list as for a heredoc). Here-strings, process
substitution, `<>`, clobber redirects and additional descriptor duplications
stay unsound. These rules grant no command permission: the command still needs
its own Bash allow rule.
