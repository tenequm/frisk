# Changelog

## [0.4.3](https://github.com/tenequm/frisk/compare/v0.4.2...v0.4.3) - 2026-10-08

### <!-- 2 -->🐛 Bug Fixes
- **probe:** stop reading a longer variable name as a write of a shorter one ([#41](https://github.com/tenequm/frisk/pull/41)) ([0bc1005](https://github.com/tenequm/frisk/commit/0bc1005c66571f0ca8c0b0d46d8b6c78b710bd78))
  A script path built from a variable is no longer reported unresolvable
  just because the command also assigns or reads a longer variable whose
  name ends the same way, such as $S beside WS=$(...) or $WS.
- **probe:** refuse variable resolution through indirect writes ([#42](https://github.com/tenequm/frisk/pull/42)) ([4715e87](https://github.com/tenequm/frisk/commit/4715e87fde388c42554e3fc25be41ad73a545d55))
  Variable-based script paths are now reported unresolvable when a builtin
  may write through an indirect name, a nameref or indirect expansion.
  This also closes the same gap in static variable resolution. No
  configuration changes are needed.

### <!-- 5 -->📚 Documentation
- **skill:** tune frisk config before changing agent instructions ([#40](https://github.com/tenequm/frisk/pull/40)) ([c8e2b6a](https://github.com/tenequm/frisk/commit/c8e2b6a088342260bd81d6287890ae7fcaf09af2))
  Documentation only: the frisk skill now says to fix a routine ask in
  frisk's own config before changing other agents' instructions, and to
  split log lines by entry so frisk check runs are not mistaken for hook
  prompts.

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.4.2...v0.4.3

## [0.4.2](https://github.com/tenequm/frisk/compare/v0.4.1...v0.4.2) - 2026-10-08

### <!-- 1 -->🎉 New Features
- **git:** sum a deletion up as loses_commits for the judge ([9a0e2ab](https://github.com/tenequm/frisk/commit/9a0e2ab36ff8c837a4e0bf244e22ea2ae8c18cdd))

### <!-- 2 -->🐛 Bug Fixes
- **judge:** say what tip_fetched shows, not that the remote still holds the commits ([6646f23](https://github.com/tenequm/frisk/commit/6646f230c9e10ceea48cda65ffcef4c8e6c01775))

### <!-- 4 -->🚜 Refactor
- **gh:** drop GraphQL query inspection, graphql is unknown ([66e9695](https://github.com/tenequm/frisk/commit/66e96955bf1eaba8f71de0c349911bc22fc2dcff))

### <!-- 5 -->📚 Documentation
- describe loses_commits ([3d7aafb](https://github.com/tenequm/frisk/commit/3d7aafbde9634f59959cbce699247b2be171152a))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.4.1...v0.4.2

## [0.4.1](https://github.com/tenequm/frisk/compare/v0.4.0...v0.4.1) - 2026-10-08

### <!-- 1 -->🎉 New Features
- **git:** record what a branch or tag deletion loses ([0b88e4e](https://github.com/tenequm/frisk/commit/0b88e4ef16babd83ecf527d04d5341e1af6ea7ff))
- **gh:** record each gh command's class and repository for the judge ([00e4675](https://github.com/tenequm/frisk/commit/00e4675a739290bde16d66ac705560257b24050a))

### <!-- 2 -->🐛 Bug Fixes
- **gh:** close record gaps that let foreign or destructive gh commands read as routine ([75253cd](https://github.com/tenequm/frisk/commit/75253cd5dbd6ba2963e1cab85bba0a02fe0fc54a))

### <!-- 4 -->🚜 Refactor
- move git parsing and repository facts into git.go ([13c8a27](https://github.com/tenequm/frisk/commit/13c8a27c9007b195318d25f261ceb4af0ad17f7e))

### <!-- 5 -->📚 Documentation
- drop the one-file rule, keep stdlib only ([51a36c6](https://github.com/tenequm/frisk/commit/51a36c60de90a5597f6e0395f1af887dba9279b8))

### <!-- 6 -->🧹 Chores
- **eval:** keep same-second eval runs from overwriting each other's results ([#37](https://github.com/tenequm/frisk/pull/37)) ([94777f9](https://github.com/tenequm/frisk/commit/94777f908f092f37a70d538cb08761e7d0962a67))
  Eval runs started in the same second no longer overwrite each other's
  results file; each run now writes its own file in the system temp dir.

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.4.0...v0.4.1

## [0.4.0](https://github.com/tenequm/frisk/compare/v0.3.0...v0.4.0) - 2026-10-07

### <!-- 0 -->🛠 Breaking Changes
- [**breaking**] ship a read-only allow baseline and generic judge prose ([#35](https://github.com/tenequm/frisk/pull/35)) ([0b1a133](https://github.com/tenequm/frisk/commit/0b1a13324e659dd2626efdbbe8618f897c1394ed))
  frisk now ships a small read-only allow baseline (ls, cat, rg, git diff,
  gh pr view and more) and measured judge prose. Put your ownership facts
  in judge.environment after "$defaults"; ask and deny rules override the
  builtins. Git aimed outside the project no longer settles statically.

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.3.0...v0.4.0

## [0.3.0](https://github.com/tenequm/frisk/compare/v0.2.1...v0.3.0) - 2026-10-06

**Upgrading:** upgrade the binary before editing the config, because an
older frisk rejects the unknown `backend` key and stays silent. Then
move `jev` under `backend`, writing `keyCmd` as `"apiKey": "$(your
command)"`. Until you do, `jev` keeps working and `frisk validate`
warns.

### <!-- 0 -->🛠 Breaking Changes
- [**breaking**] move the judge connection into the backend block ([38e07d6](https://github.com/tenequm/frisk/commit/38e07d6ab45e7365f89d3de11f04dcfc48d3f93f))

### <!-- 1 -->🎉 New Features
- **backend:** make the judge backend configurable ([#27](https://github.com/tenequm/frisk/pull/27)) ([9db8f24](https://github.com/tenequm/frisk/commit/9db8f247b821c56e642d96871e9bb521fdd00101))
  The judge's connection now lives in a `backend` block, so frisk can
  reach its judge through TypeSafe or OpenRouter. `apiKey` accepts a
  literal, `${VAR}` or `$(command)`, options take flags, and `--log-level
  debug` with `frisk check --replay` re-runs logged judge calls exactly.
- **judge:** resolve script variables, record data text, count ignored files ([#32](https://github.com/tenequm/frisk/pull/32)) ([60e8f62](https://github.com/tenequm/frisk/commit/60e8f6287c1725443686f4a47fc134c3f2f588d1))
  The judge now sees scripts that a command writes or reaches through a
  variable, a `data` list naming message, body and heredoc text the shell
  does not run, and `ignored_files` for `git clean -x`/`-X`. Reference
  `data` and `ignored_files` in your judge prose to use them.
- **probe:** attach scripts that ssh runs on a remote host ([#33](https://github.com/tenequm/frisk/pull/33)) ([1a9b16a](https://github.com/tenequm/frisk/commit/1a9b16ad99afd6ad89aea50b09847fc6e0da0ba9))
  The judge now sees scripts that ssh runs on another host: a heredoc or
  local file fed to a remote shell, or a file copied with scp or rsync and
  then run there, is attached with its host, and a script that exists only
  on the host is reported as remote-only. Nothing to configure.

### <!-- 5 -->📚 Documentation
- add frisk skill for setup, diagnosis and tuning ([debbfd2](https://github.com/tenequm/frisk/commit/debbfd2765ffbd0893665424632e591de08f904b))
- **knowledge:** drop the word cap from the judge prose budget ([#31](https://github.com/tenequm/frisk/pull/31)) ([3ecae29](https://github.com/tenequm/frisk/commit/3ecae29540a95ebd58ba0e58b5486a745c37988d))
  Documentation only: the recorded judge prose budget keeps its item
  limits and no longer caps words.
- **agents:** a breaking-change marker bumps the minor version ([e8c6796](https://github.com/tenequm/frisk/commit/e8c679631fd9208cfab8f797d748e4c64eda8611))
- **knowledge:** record what the judge evaluation showed ([#34](https://github.com/tenequm/frisk/pull/34)) ([e687ad4](https://github.com/tenequm/frisk/commit/e687ad4d326127a5ee4db32899554c0e745605a8))
  Documentation only: the knowledge base records what the judge evaluation
  showed about secret wording, where exceptions belong, and where
  rewording stops helping.
- **knowledge:** record why the deny floor stays at 0.50 ([766ab19](https://github.com/tenequm/frisk/commit/766ab19d66376ff9b322f124c0f7dee02cdbd9bb))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.2.1...v0.3.0

## [0.2.1](https://github.com/tenequm/frisk/compare/v0.2.0...v0.2.1) - 2026-10-02

### <!-- 1 -->🎉 New Features
- **static:** settle literal heredocs and screened stdin reads ([302c13a](https://github.com/tenequm/frisk/commit/302c13abc0d333693746794e893351add13bacab))

### <!-- 2 -->🐛 Bug Fixes
- **redact:** treat a name as secret only when it ends in a secret word ([366c823](https://github.com/tenequm/frisk/commit/366c823e129d985385149ee3a443ecb9ce2fdfb2))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.2.0...v0.2.1

## [0.2.0](https://github.com/tenequm/frisk/compare/v0.1.4...v0.2.0) - 2026-09-30

### <!-- 0 -->🛠 Breaking Changes
- **static:** [**breaking**] ship no default allow list and close static-tier bypasses ([#13](https://github.com/tenequm/frisk/pull/13)) ([5827553](https://github.com/tenequm/frisk/commit/582755331325bac48ae97b2d1f1f43e231f6f649))
  want from `config.example.json` into `permissions.allow`; `"$defaults"`
  there now adds nothing. Several static-allow bypasses are closed, and
  `NAME=value; cmd $NAME` chains, `gh api` GETs and `ps` can settle
  statically.

### <!-- 1 -->🎉 New Features
- **judge:** describe each git command to the judge ([#15](https://github.com/tenequm/frisk/pull/15)) ([eb34375](https://github.com/tenequm/frisk/commit/eb3437589ce1b3d43cc41ed6e16013addeb67d53))
  The judge now gets a described record for every git command: its class
  (read, local, discard, remote, exec), whether it forces, deletes a ref
  or skips hooks, where a push goes and whether that is the default
  branch, and how many files a discard would lose. Write `judge` prose
  against these fields.
- **static:** resolve variables of several words under both shell readings ([#18](https://github.com/tenequm/frisk/pull/18)) ([b674a07](https://github.com/tenequm/frisk/commit/b674a07d2bc833b521f300b5f71780d2af37dbc7))
  A variable set to several plain words, such as `C="cuttle --name box
  pw"; $C snapshot`, now settles statically when the rules allow the
  command it names. It is checked both the way bash splits it and the way
  zsh keeps it whole.
- **rules:** match git rules on the subcommand and its flags, whatever the spelling ([#20](https://github.com/tenequm/frisk/pull/20)) ([689f7c4](https://github.com/tenequm/frisk/commit/689f7c43acddb7d8965b45e74e56f624e7a74d2a))
  Git rules now match the command git runs, whatever the spelling: `git
  status *` covers `git -C dir status`, and flags in a rule match
  anywhere, so `git commit --no-verify *` replaces its positional
  variants. An allow rule never covers a force, delete or hook-skipping
  flag it does not name.
- **static:** settle loops with static bodies and redirects into paths an Edit rule allows ([#23](https://github.com/tenequm/frisk/pull/23)) ([11f9def](https://github.com/tenequm/frisk/commit/11f9def92329ec4cbef40b7b5e3b55c6bf0ecc55))
  Loops whose bodies are allowed commands (`for f in a b; do wc -l $f;
  done`, `until test -f x; do sleep 5; done`) now settle statically, and
  so do redirects and `tee` into paths an `Edit(...)` rule in
  `permissions.allow` covers, such as `Edit(/tmp/**)`.
- **static:** resolve $HOME and $TMPDIR from the hook's environment ([#24](https://github.com/tenequm/frisk/pull/24)) ([4bd750e](https://github.com/tenequm/frisk/commit/4bd750e1122dad78ae1fa37505a676d72de61d75))
  `$HOME` and `$TMPDIR` now resolve in statically allowed commands,
  directly or through a variable set from them, so reads like
  `F=$HOME/notes/x.md; wc -l $F` settle without the judge. Every
  credential screen still runs on the resolved path.

### <!-- 2 -->🐛 Bug Fixes
- **static:** close the remaining static-allow holes ([#17](https://github.com/tenequm/frisk/pull/17)) ([89e4685](https://github.com/tenequm/frisk/commit/89e4685e663f3230cec69e241c2c798ce85439f5))
  More commands that only look read-only now pass through instead of
  settling statically: a relative read after `cd` into a credential
  directory, `go vet -vettool`, `go env -w`, `uniq in out`, `yq -s`,
  `kubectl --kubeconfig`, and a leading glob on verbs with exec or write
  flags (`rg x *.go`).
- **probe:** stop long paths from withholding script bodies as credential-shaped ([#19](https://github.com/tenequm/frisk/pull/19)) ([223eb09](https://github.com/tenequm/frisk/commit/223eb093ac2818ebb159d852f6c3714dbf63e01c))
  Scripts that mention long file paths are no longer withheld from the
  judge as if they held a credential, so more script runs get judged on
  their actual body.
- **rules:** set git global options aside in the positional fallback too ([#21](https://github.com/tenequm/frisk/pull/21)) ([8fbcf99](https://github.com/tenequm/frisk/commit/8fbcf993918836862c5c17937393589067f2f4e6))
  `git -C dir status -sb` and similar commands with bundled flags git's
  matcher cannot place now match plain rules like `git status *` again.
- **static:** refuse redirects into every path Claude Code protects ([#25](https://github.com/tenequm/frisk/pull/25)) ([f2d4de3](https://github.com/tenequm/frisk/commit/f2d4de3e65463a90cb357d1e99d894a66df9f856))
  Redirects and `tee` into files Claude Code protects (shell rc files,
  `.gitconfig`, `.cargo`, `.vscode`, `lefthook.yml`, `.mcp.json` and the
  rest of its list) no longer settle statically, even when an `Edit(...)`
  rule covers them.

### <!-- 5 -->📚 Documentation
- **knowledge:** record the git record decision and the secrets prose finding ([#16](https://github.com/tenequm/frisk/pull/16)) ([cea11da](https://github.com/tenequm/frisk/commit/cea11da9e8cc959bb2e3d4fa501759dea1dd6119))
- **knowledge:** record shell word splitting, whole-chain judging and git rule matching ([#22](https://github.com/tenequm/frisk/pull/22)) ([d3f5ad9](https://github.com/tenequm/frisk/commit/d3f5ad91cbffbf8d1dea3b8123954e99bdb69b6b))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.1.4...v0.2.0

## [0.1.2](https://github.com/tenequm/frisk/compare/v0.1.1...v0.1.2) - 2026-09-30

### <!-- 2 -->🐛 Bug Fixes
- **static:** stop a quote inside a # comment from hiding the following lines ([9811be3](https://github.com/tenequm/frisk/commit/9811be322e8af4e89e1d2fc013844b00e671e775))

### <!-- 6 -->🧹 Chores
- **release:** never cancel a build on main, and let a retry reuse a leftover draft ([#10](https://github.com/tenequm/frisk/pull/10)) ([bad6b87](https://github.com/tenequm/frisk/commit/bad6b8763dbf187570e90f74cb33309b1fc7d4f9))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.1.1...v0.1.2

## [0.1.1](https://github.com/tenequm/frisk/compare/v0.1.0...v0.1.1) - 2026-09-30

### <!-- 1 -->🎉 New Features
- **judge:** let config choose which decisions the judge issues ([0b27374](https://github.com/tenequm/frisk/commit/0b27374935727805981a281092c3c39056857868))
- **log:** redact secret-shaped values before writing the log ([288777c](https://github.com/tenequm/frisk/commit/288777ca6e204cf79f3789117716401f781cd15e))
- **judge:** redact secret literals in the command sent to the judge ([f54ddaf](https://github.com/tenequm/frisk/commit/f54ddaf83696536582a2524ceb36cce9fb41f1ab))

### <!-- 2 -->🐛 Bug Fixes
- **probe:** stop reading heredoc bodies as shell commands ([cfcefc4](https://github.com/tenequm/frisk/commit/cfcefc4a6a0218483aa5a974c3437ab8e9a1d88a))
- **probe:** probe heredoc bodies piped into a shell ([f65b3ec](https://github.com/tenequm/frisk/commit/f65b3ec7c6e389d2f792b9075160e52d1de337ec))
- **probe:** probe heredoc bodies a shell reads through - or /dev/stdin ([37ab271](https://github.com/tenequm/frisk/commit/37ab27136a3003c2e99c8babbe16f880383828f9))

### <!-- 5 -->📚 Documentation
- **knowledge:** record judge.decisions, classifier timing and replay skew ([#8](https://github.com/tenequm/frisk/pull/8)) ([5edcad0](https://github.com/tenequm/frisk/commit/5edcad0d6dd8489e4632794f462aaa1a00360b4f))

### <!-- 6 -->🧹 Chores
- **release:** build every artifact before the tag exists ([#7](https://github.com/tenequm/frisk/pull/7)) ([5d26d2d](https://github.com/tenequm/frisk/commit/5d26d2d0891f14fcd0ebe4af42cbe94ef805c429))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.1.0...v0.1.1

## [0.1.0](https://github.com/tenequm/frisk/releases/tag/v0.1.0) - 2026-09-30

### <!-- 1 -->🎉 New Features
- initial frisk - PreToolUse gate with static tiers and Jev judge ([73ae5af](https://github.com/tenequm/frisk/commit/73ae5aff858c4497c9ba28ba30e99a6f9b4e6855))
- probe scripts behind wrappers, explain judge verdicts, close static holes ([091465e](https://github.com/tenequm/frisk/commit/091465e54b3643408502c715ec4fa2fe79b2c5ee))
- **hook:** gate Edit, Write and NotebookEdit with path rules and builtin guardrail paths ([2a28520](https://github.com/tenequm/frisk/commit/2a28520ffcd938e38c2b525138dbe9f6c8c2343c))
- **cli:** add validate subcommand ([a82017a](https://github.com/tenequm/frisk/commit/a82017ab15c0c8e45414a5859b9deb7c195eb52a))
- **release:** publish releases to Homebrew and add a version command ([#1](https://github.com/tenequm/frisk/pull/1)) ([398936c](https://github.com/tenequm/frisk/commit/398936cf8a996f8237d974c7e774c9656a7438b6))
  frisk now installs with `brew install tenequm/tap/frisk`, with signed and notarized macOS binaries. `frisk --version` (or `-V`, or `frisk version`) prints the build's version.
- **probe:** resolve literal shell variables in script paths and cd targets ([#3](https://github.com/tenequm/frisk/pull/3)) ([c1f6764](https://github.com/tenequm/frisk/commit/c1f67645f6db252ccbbb3670546a04e09df7bc6d))
  The judge now reads the script a command runs when its path or `cd` target comes from a variable the command sets once to a literal (`S=/tmp/x; bash $S/run.sh`), and scripts inside `if` and `for` bodies. These commands used to prompt as unresolvable.
- **static:** tolerate stderr merges and /dev/null redirects ([#5](https://github.com/tenequm/frisk/pull/5)) ([86989f9](https://github.com/tenequm/frisk/commit/86989f9b275c9e35f69ae3a38f8b55245ca7a853))
  Read-only commands that merge stderr (`2>&1`) or discard output to
  `/dev/null` are now allowed statically instead of going to the judge.
  Log rows record whether they came from `frisk hook` or `frisk check`,
  plus the judge's token usage.

### <!-- 2 -->🐛 Bug Fixes
- **static:** close credential-path, flag, env-prefix, and glob allow holes ([9b552c2](https://github.com/tenequm/frisk/commit/9b552c2adbacdcb1ef4e1eadb5c1ea2415ffeb50))

### <!-- 5 -->📚 Documentation
- **ops:** document classifier corpus and ignore its database ([0b7a889](https://github.com/tenequm/frisk/commit/0b7a889e729a8e19ea793ccb933779b5a7925def))
- **ops:** add classifier cost analysis from corpus stress-test ([bf0c965](https://github.com/tenequm/frisk/commit/bf0c9653024f519f4bc49dfd1c71bf50e523be6c))
- **knowledge:** start the knowledge bundle with design decisions and findings ([3ed904f](https://github.com/tenequm/frisk/commit/3ed904f54c57d2420385763237aeb14e3d1904de))
- **knowledge:** record the confidence floors and the unseen-script finding ([b5e2508](https://github.com/tenequm/frisk/commit/b5e2508bc3eec223a6e177925c382defd62f9b69))

### <!-- 6 -->🧹 Chores
- **eval:** add fixture replay harness with anonymized corpus fixtures ([194ee49](https://github.com/tenequm/frisk/commit/194ee49c9238a088617b16632136d81e874ae99e))
- **eval:** grade static-only expectations by tier and save the full report ([86a93b4](https://github.com/tenequm/frisk/commit/86a93b4a4f0e1f2a8df070f26a8fc3f422c420d5))
