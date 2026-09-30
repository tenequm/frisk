---
type: Reference
title: Jev API facts frisk depends on
description: Pricing, limits, context size, how confidence is computed and measured latency for the pinned judge model.
tags: [judge, jev, vendor]
status: stable
stale_after: "2026-12-31T00:00:00Z"
generated: { by: claude-code/opus-5-5, at: "2026-09-30T13:07:00Z" }
sources:
  - id: models
    resource: https://docs.typesafe.ai/models
    title: TypeSafe models
  - id: confidence
    resource: https://docs.typesafe.ai/confidence
    title: Jev confidence
  - id: choice
    resource: https://docs.typesafe.ai/primitives/choice
    title: Choice primitive
  - id: jagged
    resource: https://docs.typesafe.ai/model-jaggedness/jev-1.13
    title: Jev 1.13 jaggedness
  - id: measured
    resource: replays of about 1,800 judged `frisk check` calls each, before and after commit 091465e, and one live fixture eval of 317 judged calls, all on 2026-09-30 from one macOS machine (results not committed)
    title: Measured judge latency
---

# Model and limits

- The judge model is pinned as `jev-1.13.0`. The aliases `jev-latest` and
  `jev-preview` move when a release ships, so thresholds tuned against one version
  need the versioned id.[^models]
- Price: 0.042 USD per million input tokens. Output tokens are free.[^models]
- Rate limits: 100K tokens per second and 40 requests per second. The vendor says
  these can change without notice.[^models]
- Context: 64k tokens per request, and 32k for the state plus the longest single
  question.[^models]
- Input is text only: a string, a JSON object, or an array of text values.[^models]
- Jev is not fine-tuned per account. Domain rules go in the state, instructions
  and criteria of each request.[^models]

# Behavior that shapes the request

- A Choice answer carries the selected option, a probability for every option, and
  a `confidence` value computed from how concentrated those probabilities are. It
  is not the probability that the answer is correct.[^confidence]
- Several questions in one request are evaluated in parallel against the same
  state. Extra questions cost input tokens and little latency.[^choice]
- Jev does not generate text, so it cannot explain a verdict. Any explanation has
  to be assembled from classification outputs.[^jagged]
- Known weak spots for jev-1.13: literal reading of instructions, indirection and
  double negatives, large state with irrelevant detail, contradictory criteria,
  and content written to steer the answer. State is not treated as hostile by
  default.[^jagged]

# Measured

With a single Choice question, a judged `frisk check` call took 0.30 to 0.32s at
the median and 0.37 to 0.46s at the 90th percentile, including process start and
fetching the key. With the three-question request and git facts added in commit
091465e it took 0.39 to 0.41s at the median and 0.52 to 0.56s at the 90th
percentile.[^measured]

[^models]: TypeSafe models
[^confidence]: Jev confidence
[^choice]: Choice primitive
[^jagged]: Jev 1.13 jaggedness
[^measured]: Measured judge latency
