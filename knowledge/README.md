# Knowledge base — KQL detection engineering

Structured reference distilled from the BluRaven *Advanced KQL Threat
Hunting & Detection Engineering* course (and other public sources).
Designed to be:

1. **Scannable** — short entries, tight prose, code first.
2. **Prompt-injectable** — generate.py reads the most relevant
   snippets and includes them as few-shot anchors in the LLM-driven
   detection-generation prompt.
3. **Forkable** — every entry has a stable id (e.g. `pattern-process-tree`)
   so the prompt template can request specific anchors.

## Files

| File | Purpose |
|---|---|
| `kql_fundamentals.md` | Three statement types, pipe semantics, data types, exploration operators, project family. (Course Section 3.) |
| `kql_searching_filtering.md` | The 4-character index rule, search operator, has/contains/matches-regex semantics, where vs. and, timestamp-first ordering. (Course Section 4.) |
| `kql_scalar_functions.md` | isempty / isnull, ipv4 family, path & regex escaping, JSON bracket vs. dot, parse_json. (Course Section 5.) |
| `kql_combining_data.md` | union (with kind=, isfuzzy, withsource), join — picking the right `kind=`, M365D process-key joins. (Course Sections 6 + 7.) |
| `kql_aggregation_anomaly.md` | externaldata feeds, time-traveling sets, summarize/arg_max/conditional aggregation, mv-expand, render charts, alert-context query, static & dynamic anomaly detection, series_decompose_anomalies. (Course Sections 8 – 13.) |
| `kql_patterns.md` | Reusable query shapes — process-tree pivots, time-window joins, behavioural baselining. |
| `kql_tables.md` | Per-table recipes (DeviceProcessEvents, EmailEvents, IdentityLogonEvents, etc.). What columns matter, common predicates, joins. |
| `kql_antipatterns.md` | Common mistakes the course flags + how to fix them. |
| `kql_examples.md` | Annotated full queries from the course used as few-shot anchors. |

## Conventions

- Every code block is **runnable** in Defender Advanced Hunting unless tagged `// SKETCH:` in its first line.
- Use schema column names exactly as they appear in `data_sources/defender_spec_tables.json` (case-sensitive).
- Comment why each filter exists — not what it does.
- When citing the course, use blockquotes: `> Course (Module 4): ...`.

## How this is consumed

- `generate.py` → `_LLM_UC_PROMPT` → loads relevant patterns based on
  article content / actor TTPs and includes them as few-shot examples.
- An optional MCP server can expose these as `search_kql_pattern(query)`
  for other tools (Cursor, claude.ai web).
