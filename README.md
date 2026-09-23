# frisk

A quick pat-down for every command your agent runs.
The clean ones walk through. The rest wait for you.

A Claude Code `PreToolUse` hook for Bash: static rules first, a [Jev](https://docs.typesafe.ai) judgment for the gray zone, silence otherwise - so anything it can't vouch for falls back to Claude Code's own permission flow.

```sh
go install github.com/tenequm/frisk@latest
cp config.example.json ~/.config/frisk/config.json
frisk check 'git status | head'
```

Register `frisk hook` as a `PreToolUse` hook with matcher `Bash`. Design: [DESIGN.md](DESIGN.md).
