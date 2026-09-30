---
type: Finding
title: Secret rules must name the destination, not the act
description: Judge prose that forbids handling or moving secrets blocks routine transfers between a user's own stores; prose that forbids a secret becoming readable, or reaching a named kind of outside destination, does not.
tags: [judge, secrets, prose]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T16:40:00Z" }
sources:
  - id: dryruns
    resource: `frisk check` dry runs against one user's config before and after its secrets prose was rewritten, 2026-09-30 (no durable link)
    title: Secrets prose dry runs
  - id: maintainer
    resource: maintainer instruction on 2026-09-30 (no durable link)
    title: What the user cares about with secrets
---

# Finding

A deny line that describes an act ("reading a secret store", "forging or minting
authentication material", "sending a secret to a remote service") also matches
the routine case where a value is piped from one of the user's own stores into
another, or into the CLI that consumes it. Four variants of such a transfer were
denied at 0.27 to 0.53 under act-shaped prose. After the rewrite the same
command was allowed at 0.97.[^dryruns]

The encoding in the command (base64, `tr`) and the script probe were checked as
causes and ruled out: the rule wording alone decided it.[^dryruns]

# Rule

Write secret prose around what the user is protecting, in two parts:[^maintainer]

- A secret value must not become readable by the agent: printed to the terminal
  or transcript, or left in a file after the command ends. Say explicitly that a
  value only piped into a program, into another store, or into a temporary file
  the same command deletes is not displayed.
- A secret value must not reach a destination outside the user's control. Name
  the kinds of destination (paste sites, webhook collectors, file-drop and tunnel
  services, raw IP addresses, anything other people can read such as an issue,
  pull request, gist or commit) and name what is not covered: the provider's own
  API, the user's own services and hosts, local CLIs that consume the value.

After the rewrite, a secret sent to a webhook collector was denied at 0.99, a
secret piped into an issue comment at 0.88, and printing a secret at 0.75, while
piping into a consuming CLI was allowed at 0.94.[^dryruns]

This is one case of
[judge prose having to name routine work](judge-prose-must-name-routine-work.md):
the judge applies a line literally, so an exclusion that is obvious to the user
has to be written down.

[^dryruns]: Secrets prose dry runs
[^maintainer]: What the user cares about with secrets
