# Classifier cost analysis (2026-09-29)

Findings from five independent analyses over `classifier.duckdb` (see [AGENTS.md](AGENTS.md)): per-call overhead isolation, daily wall-time impact, denial cost, local-gate coverage ceiling, and perceived-latency skepticism. Window for allow-timing work: 2026-09-17 17:03 UTC to 2026-09-29 (approvals logged only from then); denials cover the full 30-day window. Hosts and projects are anonymized (host A = primary laptop with the local allowlist hook deployed; hosts B and C = Linux workstations without it).

## Verdict

The classifier costs real time, but mostly machine time, not staring time. The strongest case for a local gate is denial quality and reliability (false-positive denials, a worsening no-verdict failure mode), with latency a meaningful side benefit that a ~49%-coverage local gate cuts roughly in half.

## 1. Per-call overhead: ~1.3s fixed (range 1.1-1.6s, floor ~0.85s)

- Confirmed four ways: matched command heads (weighted median delta 1.28s), trivial-command floors (p05 gap 0.85s), Edit/Write with ~0.05s execution (1.0-1.4s), background-ack gap (1.20s vs 0.07s).
- Flat across command-speed quintiles (delta 1.1-1.7s while the slowdown ratio falls 12x to 1.2x): a true fixed round trip, not proportional cost.
- Grows with context: ~1.5s under 100 session events, ~2.4s past 1k. Main sessions pay more than subagents (1.9s vs 1.5s), suggesting the classifier reads the conversation.
- Parallelism hides only ~12% (92.3% of classifier-allowed foreground Bash calls overlap no other call; 2nd+ calls in a parallel batch pay ~0.18s). Backgrounding does not escape it (gate runs before launch). Effective cost ~1.1s/call.
- Exact-command matching is impossible: a command string always takes the same path through the local hook, so the two populations are nearly disjoint; head matching covers ~32% of classifier calls.
- Baseline: local hook allow path p50 0.17s wall vs 1.74s classifier-allowed (foreground Bash).

## 2. Daily bill (7 clean days, 09-22 to 09-29 excl. one idle day; 1.25s central, 1.0-1.5s sensitivity)

| Scope | Typical active day |
|---|---|
| All sessions, summed wall | ~86 min (range 70-102; worst day 139) = 11.7% of tool-execution time, 2-3.6% of session-active time |
| Main sessions only | ~29 min (max 50) |
| Actually watched (human msg < 5-10 min old) | ~15 min |
| Denials + no_verdict, full bill incl. recovery | ~9-13 min |

- Volume: 31,455 evaluated calls in-window (31,290 allowed / 127 denied / 38 no_verdict); 23.8k Bash, plus Edit, Write, Agent, and MCP tools. Read and Grep are never evaluated. 69% of volume is subagent sessions.
- Perceptibility: p50 per-turn overhead is 1.3s (dust), but ~50 turns/day carry >5s and ~11/day carry >15s of gate latency; p99 turn is 36s. 30% of allowed foreground Bash calls sit in bursts of 5+ back-to-back calls; a median burst (6 calls over 52s) gains 7.5s.
- Loop share: the median working loop is ~5.5s model gap + 1.7s call wall, so the gate is ~17% of loop time. Aggregate share of turn time is 2-4%; median per-turn share ~7%.
- Per session: main p50 50s / p90 285s / max 37 min of attributable time; 12 main sessions lost >5 min.
- Subagent wait is real and mostly attended: 72% of subagent calls (15,497 of 21,599) ran while the parent's last human message was under 10 min old, i.e. during fan-outs plausibly being waited on. Inside one subagent the cost is serial and additive (p50 24s / p90 69s / max 7 min per subagent session; 351 subagent sessions lost >30s); what reaches the user is the max over parallel lanes, not the sum, but serial pipelines add fully. Counting subagent calls into their parent's turn, 455 turns exceeded 15s and 128 exceeded 60s of gate latency (vs 132/20 for main-session calls alone). Honest attended total: ~15 min/day (main, watched) plus the slowest-lane share of ~35 subagent min/day, i.e. roughly 20-30 min/day of experienced wall, concentrated in waits on fan-outs.

## 3. Denials: the quality problem (full window, 378 denied + 38 no_verdict)

- Median denial wait 27.4s (vs 1.7s for an allow), improving over time (p50 32s -> 22s). Denial rate ~2 per 1k tool calls, no version drift.
- ~19% of Bash denials (12-32% depending on similarity threshold) were retried nearly verbatim and passed: pure friction. Another ~7% were structurally read-only commands (file reads, `git status`, disk-usage listing) denied under substantive-sounding categories.
- Of 53 denials where a human message preceded the next tool call, 40 were overrides ("retry, I approve"); the human answered within 5 min in 44 of 50 cases. The classifier mostly blocks the operator's own infra operations.
- The measured bill counts only direct wait plus the first hop to the next tool call (median ~5s). The full detour is larger and mostly unmeasured: for the ~19% verbatim-retry share the detour is trivial, but the rest was reworded into alternative (sometimes structurally worse) approaches costing several extra loop iterations each; at ~14 denials/day even 1-2 min of detour each adds another ~15-30 min/day of agent time in the worst weeks. The interruption cost is also uncounted: ~50 human context switches in 30 days to rubber-stamp overrides. Detours taken pre-emptively, without a logged denial, are invisible to the corpus entirely.
- no_verdict (classifier unavailable) is new and worsening: zero for 26 days, then 38 in the last 3 (2.4 per 1k calls in the last partial week). One burst put 31 calls across 5 sessions and 2 hosts simultaneously; during it, identical retries mostly failed again (16 retries, 2 passed, 2 fell to permission prompts) and one call hung 418s. An outage therefore does not cost 5s per call: it wedges every auto-mode lane on the affected host until the service recovers or a human intervenes, exactly the shape of a parallel fan-out. Earlier in the window, 14 more infra failures surfaced as denials ("Stage 2 classifier error", "no explanation") with a median 122s wait. A local gate removes this availability dependency.
- Real signal exists: roughly a third of denials were consequential (pushes/merges to shared branches, hard resets, credential materialization into headers, token forging from a read secret, launch-agent persistence, permission-settings self-modification). A replacement cannot be a rubber stamp.
- Top denial categories after the labeling change: Modify Shared Resources, Credential Materialization, Interfere With Workloads, External System Writes, Git Destructive, Secret-Store Writes, Credential Exploration, Merge Without Review.

## 4. Local-gate coverage ceiling (23,148 classifier-evaluated foreground Bash calls)

| Tier | Adds | Cumulative | Classifier denials inside |
|---|---|---|---|
| v0: current static allowlist hook, deployed everywhere | 14.5% | 14.5% | 0 |
| v1: + obvious verb extensions (test/build/lint runners, read-only sqlite, read verbs of multi-verb CLIs) | 5.1% | 19.6% | 1 |
| v2: + compound parsing: vars, `$()`, `/dev/null` redirects, loops | 20.4% | 40.0% | 9 |
| Rules tier: project-scoped writes (cwd, /tmp, scratchpad, worktree slots; no merges, no `.git` internals) | 9.3% | 49.3% | 7 |
| Judge-only residue | 50.7% | - | 84 |

- The classifier allowed 99.4% of this residue, so the residue is almost entirely safe in practice; most denials inside the safe buckets look like classifier false positives.
- The hook only runs on host A. 11.2% of the residue is calls on hosts B/C that today's hook would already allow: free coverage by deploying it.
- 3-10% of hook allows (from cc 2.1.278 on) still triggered the classifier anyway; a local gate cannot save those unless the harness honors the allow.
- Residue character: `python3` heads are 16.4% (mostly inline heredoc snippets: 44% of the judge-only bucket, ~5.1k calls; ~1.1k look read-only by regex), `git` 11.4%, `rg` 9.8%, `sed` 7.3%, `cat` 6.2%, `ssh` 5.6%. Read-only verbs land in the residue mainly because of `$VAR`, `$()`, or `2>/dev/null`, not because of what they do.
- Concentration: exact-command dedup is useless (top 100 = 1.2%); head+subcommand top 50 = 83%. Safety depends on parsing, not lists.
- Bug found in the current hook while bucketing: a cloud-CLI secret-read subcommand (`... secrets versions access`) passes its read check because the verb sets miss `access`; the classifier denied the same call as Credential Materialization. Patch the verb set regardless of frisk.

## 5. Bottom line

The latency dust (~86 min/day summed, ~20-30 min/day experienced once subagent fan-out waits are counted) is the floor. On top of it sits a fatter, harder-to-sum tail: denial detours and workaround hunting (~15-30 min/day in bad weeks), ~50 human interruptions per month for rubber-stamp overrides, and availability wedges that stall whole parallel fan-outs at once. The tail lands precisely on attended, high-parallelism work, and it is the part a local gate eliminates entirely rather than halves. A ~49%-coverage local gate cuts the dust roughly in half; owning the decision locally removes the junk-denial share (~26%), the interruptions it causes, and the no-verdict outages. Cheapest wins in order: deploy the existing hook to the hookless hosts (11% free), patch the secret-read hole, extend the verb sets (v1), then the compound-command parser is the single component that pays for itself (+20 pts alone). The inline-interpreter residue (~16% of evaluated calls) is where a judge tier earns its keep.

## Method notes

- Wall time per call uses the ASOF formula in [AGENTS.md](AGENTS.md) (result_ts minus the latest of own tool_use, last tool_use before the result, previous result), which nets out parallel calls.
- "Watched" = main-session events whose last typed human message is under 5-10 min old. permission_mode cannot separate interactive from autonomous (98% of evaluated calls are in auto).
- Retry detection: whitespace-token Jaccard >= 0.7 against the next 3 Bash commands (0.5 and 0.9 give the 12-32% band). Prefix matching is useless (`cd <path> &&` prefixes collide).
- Before 09-17, a passed retry could have been a user-approved permission prompt (approved prompts leave no record), so the false-positive share is a floor-to-ceiling band, not a point.
- One host's approvals were also unlogged before ~09-21 despite the 09-17 cutoff; daily figures use 09-22 onward.
