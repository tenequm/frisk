---
type: Reference
title: The judge request is served by more than one vendor
description: TypeSafe's System One request shape is also served by OpenRouter, for Jev and for other vendors' decision models, so the backend is configuration; calibration differs per model.
tags: [judge, backend, vendor]
status: stable
stale_after: "2027-01-06T00:00:00Z"
generated: { by: claude-code/fable-5, at: "2026-10-06T13:20:00Z" }
sources:
  - id: sdk
    resource: https://openrouter.ai/docs/guides/community/typesafe-sdk
    title: Jev SDK for TypeScript and Python on OpenRouter
  - id: decisions
    resource: https://openrouter.ai/docs/api/api-reference/alphadecisions/submit-a-decisions-request
    title: OpenRouter Decisions API reference
  - id: gate
    resource: https://openrouter.ai/docs/cookbook/building-agents/gate-tool-calls-with-jev
    title: Gate Agent Tool Calls with Jev
  - id: probe
    resource: frisk's own judge request (live config prose, decision plus both attribution questions) sent by hand on 2026-10-06 to three commands with known verdicts, against each endpoint and model below (results not committed)
    title: Backend probe
---

# Who serves the request

- TypeSafe serves the System One request (`model`, `state`, `questions` in;
  `model`, `answers`, `usage` out) at `https://api.typesafe.ai/v1/systemone`.
  This is `backend.endpoint`'s default.
- OpenRouter implements the same shapes at
  `https://openrouter.ai/api/v1/systemone`, billed to an OpenRouter key, and adds
  `id`, `provider` and `usage.cost` to the response.[^sdk] Its alpha
  `https://openrouter.ai/api/alpha/decisions` takes the same body.[^decisions]
  frisk's request parses unchanged from both.[^probe]
- OpenRouter maps bare TypeSafe model ids (`jev-1.13` to `typesafe/jev-1.13`,
  `jev-latest` to `~typesafe/jev-latest`).[^sdk] TypeSafe's patch-level id
  `jev-1.13.0` does not exist there and returns 400.[^probe]

# Models are not interchangeable

OpenRouter serves decision models from several vendors through the same request,
so a model switch is one config value. On frisk's request the results
differed:[^probe]

| Model | Verdicts right (of 3) | Latency | Probabilities |
| --- | --- | --- | --- |
| `typesafe/jev-1.13` | 3 | 0.3-0.5s | spread, e.g. allow 0.80 / ask 0.11 |
| `inception/mercury-decide:free` | 3 | about 1s | about 0.9999 on every answer |
| `upstage/solar-decide` | 3 | 13-19s | near 1.0 |
| `jaredpalmer/kev-4b` | 0, `defer` every time | about 1.1s | flat |

The [confidence floors](confidence-floors.md) were measured on Jev's
distribution. A model that reports near-certainty on everything defeats them,
and one slower than the hook timeout is silence on every call, so a new model
needs its own replay before it decides.

Identical requests also move Jev's probabilities: the same allow scored 0.80,
then 0.75 twice, in one session,[^probe] and OpenRouter measured swings of up to
0.08.[^gate] A command whose probability sits near the allow floor flips between
allow and silence across runs.

[^sdk]: Jev SDK for TypeScript and Python on OpenRouter
[^decisions]: OpenRouter Decisions API reference
[^gate]: Gate Agent Tool Calls with Jev
[^probe]: Backend probe
