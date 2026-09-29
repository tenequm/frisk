# classifier-data

`classifier.duckdb` is a local (gitignored) corpus of Claude Code sessions for analysing tool-call gating: what agents and users did, what the auto-mode classifier and hooks decided, and when. It holds facts only - no labels, scores or judgements.

- Source: [pond](https://pond.locker/) `pond sql` exports of every Claude Code session (main and subagent, all hosts), loaded into DuckDB.
- Window: 2026-08-31 07:30 UTC to 2026-09-29 20:37 UTC (the last day is partial). 321,242 events, 3,439 sessions.
- Open with `duckdb -readonly classifier.duckdb` (DuckDB >= 1.5; the file uses storage version v1.5.0).
- DuckDB docs: [sitemap](https://duckdb.org/sitemap), [llms.txt](https://duckdb.org/llms.txt).

## `events`

One table, one row per session event, sorted by `ts`. Order within a session is `seq`. No constraints or indexes, per DuckDB's performance guidance.

| `kind` | What | Rows |
|---|---|---|
| `tool_call` | Agent tool call, merged with its result | 175,411 |
| `assistant_thinking` | Non-empty thinking block | 83,618 |
| `assistant_text` | Assistant text block | 42,148 |
| `user_message` | User-role message, including subagent task prompts and task notifications (see `origin_kind`) | 18,775 |
| `mode_change` | Permission-mode record | 584 |
| `compact_boundary` / `compact_summary` | Context compaction marker and its summary | 317 / 317 |
| `user_shell` | A `!` command the user ran, merged with its output | 72 |

Excluded at load: Claude Code's injected meta messages (`isMeta`: system reminders, skill bodies, caveats) and bookkeeping records (titles, token reminders, queue operations).

### Columns

**Provenance and order**
- `session_id`, `parent_session_id`, `parent_message_id` - pond ids; subagents are their own sessions, linked to the parent session and the message that spawned them.
- `message_id` - pond message id of the event (for `tool_call`: the assistant line with the `tool_use`); `result_message_id` - the result line (`tool_call`, `user_shell`).
- `anthropic_message_id`, `request_id` - API turn and request ids (assistant events).
- `source_line`, `result_source_line` - line numbers in the original session JSONL.
- `seq`, `ts`, `next_event_ts` - position in the session, event time, time of the next event.

**Content**
- `text` - message/thinking text; for `user_shell` the command; for `mode_change` the new mode.
- `origin_kind`, `prompt_source` - Claude Code's own origin fields on user messages (`human`/`typed`, `task-notification`/`system`, ... ; NULL for subagent task prompts).
- `tool_name`, `call_id`, `tool_input` (JSON, full input).
- `result` - full result text (images as `[image]`); `result_is_error`; `result_ts`.
- `tool_use_result` JSON - Claude Code's structured result (stdout, stderr, interrupted, file data, ...).

**Gate**
- `classifier` ENUM - `allowed` (Claude Code logged the classifier's context for this call), `denied`, `no_verdict` (classifier errored); NULL = no classifier record.
- `classifier_reason` - denial category, e.g. `[Credential Materialization].`
- `classifier_request`, `classifier_context` JSON (the git/env state sent to the classifier), `classifier_meta`.
- `user_rejected` - result is Claude Code's "The user doesn't want to proceed" text (a rejected permission prompt).
- `hooks` - list of hook records for the call: `hook_event`, `type`, `hook_name`, `command`, `exit_code`, `duration_ms`, `decision` and `decision_reason` (parsed from the hook's JSON stdout), `stdout`, `stderr`, `content`, `ts`, `message_id`, as Claude Code logged them; a hook run it did not log is absent.
- `permission_mode`, `permission_mode_from_parent` - last recorded mode at `ts`; subagents inherit their parent's (or grandparent's) mode.

**Referenced files** (`tool_call` Bash and `user_shell`)
- `referenced_files` - files this session wrote with `Write` earlier whose path appears in the command text (absolute, `~/`, or relative to `cwd`): `path`, `content` as written, `written_ts`, `write_message_id`, `changed_after_write` (a later Edit/Write touched the path before this command). This is the only reliable way to recover script contents; files that were never written in the session are absent.

**Environment**
- `model`, `effort` (assistant events), `source_agent`, `is_subagent`, `project`, `host`, `cc_version`, `entrypoint`, `cwd`, `git_branch`.

## Caveats

- Claude Code logs classifier approvals only from 2026-09-17 17:03 UTC. Before that `classifier` is NULL for approved calls too; denials are complete for the whole window. Restrict allow-rate and timing work to `ts >= '2026-09-17 17:03:18'`.
- Permission prompts that the user approved leave no record; only rejections do.
- 15 `tool_call` rows have no result (background agents, calls in flight at export).
- 568 events have no `permission_mode` (no mode record in the session or its parents).

## Example: wall time per tool call

```sql
-- result_ts minus the later of (own tool_use, last tool_use streamed before the result, previous result),
-- so parallel calls are not double counted
WITH calls AS (FROM events WHERE kind = 'tool_call' AND result_ts IS NOT NULL),
hook_allowed AS (
    SELECT session_id, call_id, bool_or(h.decision = 'allow') AS hook_allow
    FROM (SELECT session_id, call_id, unnest(hooks) AS h FROM calls) GROUP BY ALL),
timed AS (
    SELECT c.*, epoch(c.result_ts - greatest(c.ts, u.ts, r.result_ts)) AS wall_s
    FROM calls c
    ASOF LEFT JOIN (SELECT session_id, ts FROM calls) u ON u.session_id = c.session_id AND c.result_ts > u.ts
    ASOF LEFT JOIN (SELECT session_id, result_ts FROM calls) r ON r.session_id = c.session_id AND c.result_ts > r.result_ts)
SELECT CASE WHEN t.classifier = 'allowed' THEN 'classifier allowed' WHEN h.hook_allow THEN 'hook allowed' END AS path,
       count(*) AS calls, round(median(wall_s), 2) AS p50_s, round(avg(wall_s), 2) AS mean_s
FROM timed t LEFT JOIN hook_allowed h USING (session_id, call_id)
WHERE t.tool_name = 'Bash' AND t.ts >= TIMESTAMP '2026-09-17 17:03:18'
  AND NOT coalesce(json_extract_string(t.tool_input, '$.run_in_background')::BOOLEAN, false)
GROUP BY path HAVING path IS NOT NULL ORDER BY path;
```

In DuckDB 1.5.5, lambdas (`list_transform`, `list_filter`) inside grouped queries with ASOF joins can raise an internal optimizer error; `unnest` the list in a CTE instead, as above.
