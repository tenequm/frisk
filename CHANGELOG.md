# Changelog

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
