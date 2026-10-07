---
type: Finding
title: Static allow rules are a speed cache with a ceiling near half of all calls
description: A few dozen high-volume rules settle about half of real Bash calls; most of the rest have a shape no static rule can settle, so the judge prose, not the allow list, decides the interruption rate.
tags: [static, allow, judge]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-10-07T10:00:00+01:00" }
sources:
  - id: corpus
    resource: classification of 19,544 real hook Bash calls from one machine's frisk.log, 2026-09-30 to 2026-10-06, through `frisk check` with no backend configured, under several allow lists (results not committed)
    title: Static coverage measurement
---

# Finding

Over 19,544 real hook calls, the share settled by static allow barely moved with
the size of the list: 53.2% with 176 rules, 53.0% with 149, 51.2% with 63 and
50.0% with 56. The 56 rules each settled at least 20 calls in the week; the 86
rules below that line together settled 355 calls.[^corpus]

Of the calls that fell through to the judge, 91% had a shape no static rule can
settle: inline interpreter code 28.7%, a script or binary run by path 16.9%, a
shell loop or conditional 12.3%, ssh to a host 11.5%, command substitution 8.6%,
shell variables 8.3%. Only 8.9% were plain commands with no matching rule.[^corpus]

# Consequence

The allow list is kept as a cache of high-volume, unambiguous commands, sized by
measured use rather than by what is safe in principle. About half of all calls go
to the judge whatever the list holds, so the judge prose is what decides how often
the user is interrupted (see [Judge prose is a few tests over four risk
dimensions](judge-rules-four-dimensions.md)). The builtin read-only baseline is
cut by the same measure (see
[Core ships generic defaults](core-generic-config-specific.md)).

[^corpus]: Static coverage measurement
