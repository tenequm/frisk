# Changelog

## [0.1.3](https://github.com/tenequm/frisk/compare/v0.1.2...v0.1.3) - 2026-09-30

### <!-- 2 -->🐛 Bug Fixes
- **release:** cut a test release to exercise the cancel-and-retry path ([75b4f53](https://github.com/tenequm/frisk/commit/75b4f53cb7e103717d6cea4434cbff40e387ca32))

**Full Changelog**: https://github.com/tenequm/frisk/compare/v0.1.2...v0.1.3

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
