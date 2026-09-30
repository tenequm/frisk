# frisk

Claude Code PreToolUse gate for Bash. Design: [DESIGN.md](DESIGN.md).

## Core rules

- **KISS** - the simplest thing that works. One file, stdlib only, no new abstractions.
- **YAGNI** - build nothing until real traffic in `frisk.log` asks for it. No speculative config keys, flags, or tiers.

## Invariants

- frisk only shortcuts, never bypasses: every failure path is silence (no output, exit 0).
- Config is read only from `$XDG_CONFIG_HOME/frisk/`, never from the project.
- Reuse Claude Code vocabulary (`allow`/`ask`/`deny`/`defer`, `permissions.*`, `autoMode.*`); invent no new terms.
- Comments explain why, never what.
- Core stays generic for any unix user; one user's tools and policy live in config ([why](docs/knowledge/core-generic-config-specific.md)).
- Core understands, config decides: core ships no allow rules, only the parser and the screens that keep a config rule from matching a form it does not mean. With no rule a command passes through. A starting list lives in [config.example.json](config.example.json).

## Workflow

`just check` (fmt + lint + race tests) must pass before every commit. Conventional Commits.

## Releasing

Releasing is not a task. Land conventional commits on `main` and release-please
keeps a `chore(main): release X.Y.Z` PR open and current; merging that PR is the
release, and it publishes the binaries and the Homebrew cask
(`brew install tenequm/tap/frisk`) in one `ci.yml` run. Nothing here is a
judgement call, and none of it is manual:

- **Write the `## Release notes` section** at the bottom of the PR description.
  It becomes the changelog entry, verbatim, under that commit's bullet. One
  paragraph, at most 300 characters, no bullets and no blank lines, and the last
  section of the body - CI enforces every one of those and comments on the PR
  with all the failures at once. Write it for someone running frisk: what
  changed for them and what they must do. Reviewer detail goes in the sections
  above it, which never reach the changelog. A release-wide lead or an
  `**Upgrading:**` block goes after a lone `[release-note]` line, exempt from the
  cap. A commit pushed straight to `main` gets its bullet and no prose.
- **Forcing a specific version** is the one exception, and it is a
  `Release-As: X.Y.Z` footer at the very bottom of the PR body, below the release
  note. It has to be last - the conventional-commit grammar reads footers at the
  end - so the lint and the changelog template both ignore it there: it is not
  counted against the note's cap and never renders as prose.
- **Never pick a version otherwise, never hand-write or hand-edit the release PR.**
  release-please derives the version from the commit types and regenerates that
  PR on every push to `main`, discarding anything written into it. It also
  decides on its own whether a release is warranted at all - a batch of purely
  internal commits opens no PR, and that is correct, not a fault to work around.
- **Merge the release PR however you like** - the button, `gh pr merge`, any
  subject. Its payload is `CHANGELOG.md` and the manifest bump, which are files
  in the diff and land regardless of the commit message.
- **Fixing a note after merge:** edit the merged PR's description. Generation
  re-reads it (`ops/scripts/release-note-from-pr.sh`), so the correction lands in
  the next regeneration. Editing `CHANGELOG.md` by hand does nothing - it is
  regenerated from commits every time.
- **Preview locally, any time:** `git-cliff --config .github/cliff.toml
  --unreleased --tag vX.Y.Z`. Read-only, nothing to revert. The release PR also
  carries the same rendering as a sticky comment, and its `CHANGELOG.md` diff is
  the real thing - its *description* is release-please's own plainer rendering
  and must be left alone, since it parses that body on merge to decide what to
  release.
- **The squash settings are load-bearing.** The changelog prose is the PR body,
  which is only true while the repo squashes with `PR_TITLE`/`PR_BODY`. They are
  managed in `tenequm/tf-live` (`global/github/repos.tf`) along with the
  default-branch ruleset; change them there, not with `gh api`. Verify:

  ```bash
  gh api repos/tenequm/frisk --jq '{title: .squash_merge_commit_title, message: .squash_merge_commit_message}'
  ```

Who owns what, when changing any of it: release-please computes the version and
opens the release PR, and nothing else (`.github/release-please-config.json`);
git-cliff renders `CHANGELOG.md` and the GitHub release body
(`.github/cliff.toml`); GoReleaser builds the artifacts, then creates the GitHub
release and the tag (`ops/config/goreleaser.yaml`). release-please runs with
`skip-changelog`, so it and git-cliff never write the same file, and with
`skip-github-release`, so it never tags.

The tag comes last. A release is due when the manifest on `main` names a version
with no tag. The `release` job then tags in its own checkout only, builds, signs
and notarizes everything, and GitHub creates the real tag when GoReleaser
publishes the release; the cask is pushed after that. A failure before the
publish leaves no tag, no release and no cask, and re-running the job retries.
The job ends by relabelling the merged release PR `autorelease: tagged`: while
one is still `autorelease: pending`, release-please opens no new release PR.

No file carries the version:
`go build` stamps the tag into the binary and `frisk version` prints it. Two
gates enforce what used to be documented: the PR title and note
(`release-note.yml`), and the `word(` shape that makes release-please silently
drop a commit (same workflow).

## Knowledge

Durable decisions and findings live in [docs/knowledge/](docs/knowledge/index.md), an OKF bundle. Load the `okf-project-knowledge-base` skill before reading or writing it, and review what to capture at the end of substantial work.
