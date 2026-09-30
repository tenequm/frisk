# Changelog

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
