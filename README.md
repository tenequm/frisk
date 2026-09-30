# frisk

A quick pat-down for every command your agent runs.
The clean ones walk through. The rest wait for you.

A Claude Code `PreToolUse` hook for Bash: static rules first, a [Jev](https://docs.typesafe.ai) judgment for the gray zone, silence otherwise - so anything it can't vouch for falls back to Claude Code's own permission flow.

```sh
brew install tenequm/tap/frisk   # or: go install github.com/tenequm/frisk@latest
cp config.example.json ~/.config/frisk/config.json
frisk check 'git status | head'
```

Register `frisk hook` as a `PreToolUse` hook with matcher `Bash`. Design: [DESIGN.md](DESIGN.md).

frisk allows nothing on its own. The static tier settles only the commands `permissions.allow` lists, and `config.example.json` carries a read-only starting list to copy and trim; with no config every command passes through to Claude Code's own flow.

To gate file edits too, use matcher `Bash|Edit|Write|NotebookEdit` and write `Edit(<path-pattern>)` rules in `permissions.*`; frisk's own config and Claude Code's settings and hooks always ask.

`frisk validate [--live]` checks the config (a malformed one silently disables the gate); `--live` makes one real judge call. `frisk --version` (or `-V`, or `frisk version`) prints the build's version.
