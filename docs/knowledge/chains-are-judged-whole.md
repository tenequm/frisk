---
type: Decision
title: Chained commands are judged whole
description: Judging each piece of a chain separately and keeping the strictest verdict moved as many chains out of allow as into it, at 1.8 times the judge calls, and loses the context that links the pieces.
tags: [judge, chains]
status: stable
generated: { by: claude-code/opus-5-5, at: "2026-09-30T18:00:00Z" }
sources:
  - id: replay
    resource: replay of 300 chained commands from one user's frisk.log through both arms, 2026-09-30 (no durable link)
    title: Chain-split measurement
---

# Decision

The judge gets a chained command (`a && b; c`) in one call and gives one
verdict. One doubtful piece can drag the whole chain below the confidence floor,
so splitting the chain and judging each piece was measured as an alternative.
It is not built.[^replay]

# What was measured

300 chains whose whole verdict needed the judge, replayed now through the same
binary and config, whole and per piece:[^replay]

- Allowed as a whole 184, per piece 173; on a repeat run 179 and 178. Moved into
  allow by splitting: 18; moved out: 29.
- The arms disagree on 19.7% of chains, four times the 4.7% at which the whole
  arm disagrees with itself, but the net change in allows sits inside that noise.
- Per-piece judging cost 1.8 times the judge calls and 1.76 times the input
  tokens.

# Why

- Every extra judged piece is another draw against the floor: 15 of the 29
  losses were one piece just under 0.75.
- A piece judged alone loses what made it obviously fine: 8 losses were a binary
  run right after the same command built it, and `printf ... | pbcopy &&
  pbpaste` became a deny once `pbpaste` stood alone.
- The better lever for a chain sunk by one piece is to settle that piece
  statically or fix the prose that misreads it.

The sample was one week of benign traffic; it says nothing about chains built to
look innocent piece by piece, which is the risk splitting would add.

[^replay]: Chain-split measurement
