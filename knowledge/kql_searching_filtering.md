# KQL searching & filtering — operator reference + index gotchas

Distilled from BluRaven *Advanced Hands-On KQL* — Section 4
(Searching and Filtering Data). The string-index rules in this file
are the single biggest source of silent false negatives when authoring
new detections.

<!-- ============================================================== -->

## filter-string-index-rules

> **The 4-character rule.** Kusto indexes strings by alphanumeric
> *terms* — non-alphanumerics (`\`, `/`, `-`, `:`, `.`, etc.) act as
> delimiters. **Only terms ≥ 4 characters are indexed.** Predicates
> on shorter terms still work, but they fall off the index and scan.

Direct consequences for detection authors:

- `has "ps"` is slow — `ps` is < 4 chars, no index seek.
- `has "powershell"` is fast — single 10-char term, indexed.
- `has "mimikatz"` matches a path because `\`/`.`/`-` split the path
  into terms (`C:\Temp\mimikatz.exe` → terms `Temp`, `mimikatz`, `exe`).
- `has "mimikatz"` will **NOT** match `mimikatz12.exe` or
  `amimikatz.dll` — `mimikatz12` and `amimikatz` are distinct terms.

When matching short tokens (file extensions, 2-3-letter flags), reach
for `endswith` / `startswith` / `contains` consciously — they trade
index speed for substring correctness.

<!-- ============================================================== -->

## filter-search-operator

A tabular operator that scans column values for a pattern. Useful for
exploration when you don't yet know the right table/column. **Do not
use in production detections** — it scans every column of every table
in scope.

```kql
// Across the entire workspace (slow)
search "mimikatz"

// Restricted to one table
DeviceProcessEvents | search "mimikatz"
search in (DeviceProcessEvents) "mimikatz"

// Wildcards across table names
search in (*Events) "mimikatz"        // tables ending in "Events"
search in (*Logon*) "mimikatz"        // tables containing "Logon"

// Column-scoped search
search FileName:"lsass"
search FileName:"mimikatz" and InitiatingProcessFileName:"rundll32"
search FileName:"powershell" and not (RemoteIP:"10.10.10.5")

// Search-predicate wildcards (case-insensitive by default)
search "*katz"     // suffix match  → "12mimikatz.exe"
search "mimi*"     // prefix match  → "mimikatz.exe"
search "mimikatz"  // whole term    → "mimikatz.exe", NOT "mimikatz12.exe"
```

> Gotcha: when combining column-scoped predicates with `and`, every
> referenced column must exist in at least one of the searched tables.
> Otherwise the engine returns
> *"Failed to resolve scalar expression named ColumnName"*. Switch to
> `or` if a column may be absent from one of the tables.

<!-- ============================================================== -->

## filter-string-operators

| Operator | Case sens. | Match shape | Notes |
|----------|-----------|-------------|-------|
| `has` | insensitive | whole term | Indexed. Default for term-aligned matches. |
| `has_cs` | sensitive | whole term | Same speed as `has`, exact case. |
| `!has` / `!has_cs` | both | whole term | Negation forms. |
| `hasprefix` | insensitive | term begins with… | `hasprefix "Temp"` → `Temp1\test`, `Temp-34567` ✓ ; `ATemp\test` ✗ |
| `hassuffix` | insensitive | term ends with… | `hassuffix "emp"` → `\Temp\`, `\Temp-34567\test` ✓ ; `\Temp1 test\` ✗ |
| `contains` | insensitive | substring (anywhere, no term boundary) | Slower — fragment scan. Use when partial match needed. |
| `contains_cs` | sensitive | substring | Same as above, exact case. |
| `startswith` / `endswith` | insensitive | string-edge match (no term split) | Best for **path/extension** matches: `FolderPath endswith @"\Temp\"` |
| `matches regex` | **sensitive** | RE2 regex | **Case-sensitive by default** — wrap pattern with `(?i)` for case-insensitive. |
| `==` | sensitive | full string | Exact equality. |
| `=~` | insensitive | full string | Case-insensitive equality. **Default for binary names.** |
| `!=` / `!~` | both | full string | Negation forms. |

```kql
// Recommended defaults for endpoint detections
| where FileName =~ "powershell.exe"             // case-insensitive equality
| where ProcessCommandLine has "EncodedCommand"  // term-aligned, indexed
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\")
| where ProcessCommandLine matches regex @"(?i)-w(in)?(dow)?style?\s+h(idden)?"
```

### Naming convention to remember

- `_cs` suffix → case-sensitive variant (`has_cs`, `hassuffix_cs`).
- `!` prefix → negation (`!has`, `!contains`, `!startswith`).
- `~` (tilde) → case-insensitive (`=~`, `!~`).

<!-- ============================================================== -->

## filter-not-vs-bang

`not()` and `!` look interchangeable but aren't:

```kql
// `not()` is a SCALAR FUNCTION — wraps an expression
| where not(FileName has "rundll32")

// `!` is an OPERATOR PREFIX — modifies the operator
| where FileName !has "rundll32"
```

Both produce the same row set here, but the *engine plan* differs:
the operator-prefix form (`!has`) lets the engine push the negation
into the index seek; the function form (`not(...)`) evaluates the
inner predicate first and then negates. **Prefer `!has` / `!=` /
`!contains` etc. for performance.**

<!-- ============================================================== -->

## filter-where-vs-pipeline-and

These two forms are semantically equivalent:

```kql
// (a) Multiple `where` clauses — most readable, friendly to commenting
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625              // failed logon
| where TargetUserName == "svc-mssql"
| where Computer !in ("dc01", "dc02")

// (b) Single `where` with `and` — compact, harder to extend
SecurityEvent
| where TimeGenerated > ago(1d)
    and EventID == 4625
    and TargetUserName == "svc-mssql"
    and Computer !in ("dc01", "dc02")
```

> Course preference: form (a) for production detections — every
> condition can carry its own `// why this filter exists` comment, and
> reviewers can disable a single line during triage. The engine
> collapses both forms to the same plan, so there's no perf reason to
> prefer (b).

<!-- ============================================================== -->

## filter-let-allowlists

Use `let` + `dynamic([...])` to centralise allowlists / known-good
hosts / FP suppression — the same list can serve multiple `where`
clauses or feed an anti-join.

```kql
let _known_admin_hosts   = dynamic(["jumpbox-01","jumpbox-02"]);
let _known_svc_accounts  = dynamic(["svc-backup","svc-monitor"]);
let _baseline_window     = 30d;

DeviceProcessEvents
| where Timestamp > ago(1h)
| where AccountName !in (_known_svc_accounts)
| where DeviceName !in (_known_admin_hosts)
| where FileName =~ "psexec.exe"
```

> Convention: prefix list-typed `let` variables with `_` so reviewers
> can spot suppression lists at a glance (and audit them when FP rates
> change).

<!-- ============================================================== -->

## filter-timestamp-first

Microsoft 365 Defender Advanced Hunting retains data for **a maximum
of 30 days**. Microsoft Sentinel retention is configurable per-table
and per-workspace. **Always filter on the timestamp column first** —
both engines partition data on time, so a leading `where Timestamp >
ago(...)` predicate is the difference between an indexed seek and a
full table scan.

```kql
// M365 Defender — column is `Timestamp`
DeviceProcessEvents
| where Timestamp > datetime(2026-04-25 20:00:00)
| where Timestamp between ( datetime(2026-04-25 20:00:00)
                         .. datetime(2026-04-25 22:00:00) )

// Sentinel — column is `TimeGenerated`
SecurityEvent
| where TimeGenerated > datetime(2026-04-25 20:00:00)
| where TimeGenerated between ( datetime(2026-04-25 20:00:00)
                             .. datetime(2026-04-25 22:00:00) )
```

> **Between gotcha**: the earlier timestamp **must** be on the left.
> `between (laterTime .. earlierTime)` returns zero rows silently —
> no error.

> No double quotes are needed inside `datetime(...)` — the literal is
> parsed by the engine.
