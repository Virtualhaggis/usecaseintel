# KQL fundamentals — syntax, statements, data types, scaffolding

Distilled from BluRaven *Advanced Hands-On KQL* — Section 3
(KQL Fundamentals and Exploring Data). These are the building blocks
the rest of the knowledge base assumes you know.

<!-- ============================================================== -->

## fundamentals-three-statement-types

A KQL query is composed of three statement kinds, evaluated in this
order when present:

1. **`set` statements** — modify a query option for the duration of
   the query. End with `;`. Example:
   ```kql
   set maxmemoryconsumptionperiterator = 9723456780;
   ```
2. **`let` statements** — define a named expression (variable, scalar,
   tabular, or function). End with `;`. Used for reuse + readability.
   Examples:
   ```kql
   let user_name = "svc-mssql";
   let created_services =
       DeviceEvents
       | where ActionType == "ServiceInstalled";
   ```
3. **Tabular expression statement** — the actual query. Composed of a
   data source (table) + zero or more operators connected by pipes.
   The trailing `;` is recommended but optional.

> Best-practice ordering: `set` first → `let` blocks → tabular
> expression. Let blocks may be interleaved with tabular when scoping
> requires it.

<!-- ============================================================== -->

## fundamentals-pipe-semantics

The pipe `|` mirrors UNIX shell pipes — output of one operator becomes
input to the next. **Order matters** for both correctness and
performance: filter early to shrink the dataset before joins or
summarisations.

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"   // narrow
| summarize Count = count() by FileName    // aggregate
| top 10 by Count desc                     // bound output
```

Comments use `//` (single-line). Multi-line comments are not
supported.

<!-- ============================================================== -->

## fundamentals-data-types

| Type | Notes |
|------|-------|
| `datetime` | ISO 8601, **always UTC**. `2023-10-21T18:15:24` or `2023-10-21 18:15:24` (T or space). Construct with `datetime("...")` or `now()` / `ago()`. |
| `timespan` | Durations: `3d`, `2h`, `15m`, `10s`, `100ms`. Used in `ago()`, arithmetic on datetimes. |
| `string` | Escape `\` with `\\`, or use verbatim `@"C:\Path\app.exe"`. Obfuscated string — `h"..."` or `h'...'` — keeps the value out of audit logs. |
| `dynamic` | JSON-like — objects, arrays, nested structures. Built with `dynamic([...])` / `dynamic({...})`. Use `parse_json()` and `tostring()` to extract. |
| `int` / `long` | 32-bit / 64-bit whole numbers. |
| `real` | Floating-point. |
| `bool` | `true` / `false`. |

### Time helpers

```kql
| where Timestamp > ago(1h)                                  // last hour
| where Timestamp between (ago(4h) .. ago(1h))               // 4h ago → 1h ago
| where Timestamp between (datetime("2023-10-14 18:15") .. datetime("2023-10-14 19:30"))
```

`ago(1h)` is equivalent to `now(-1h)`. Defender always normalises
events to UTC — convert at presentation time, not in `where` clauses.

### String escape pattern

```kql
| where FolderPath has @"C:\Windows\Temp\"     // verbatim — preferred for paths
| where ProcessCommandLine has h"-pass mypass" // obfuscated value, kept out of audit log
```

<!-- ============================================================== -->

## fundamentals-exploration-operators

Quick-look operators for getting acquainted with a table before
writing a real detection.

| Operator | Purpose |
|----------|---------|
| `count` | Number of records. `T \| count`. |
| `take N` / `limit N` | Return first N rows (no ordering guarantee). Synonyms. |
| `sample N` | Random N rows — useful for spotting variant shapes. |
| `distinct Col1, Col2` | Distinct combinations across the listed columns (NOT distinct per column). |
| `getschema` | Show column names + types for the table. |

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| sample 50
| project Timestamp, DeviceName, FileName, AccountName
```

> Engine record caps: **Sentinel = 30,000 / M365 Defender = 10,000**.
> Lab environments may cap at 5,000. If you hit the cap, the engine
> tells you — refine the time window before paginating.

<!-- ============================================================== -->

## fundamentals-project-family

`project` and its variants reshape the column set without aggregating.

| Variant | Effect |
|---------|--------|
| `project` | **Replace** the column set. Allows rename + computed columns. |
| `project-rename` | Rename columns; keep all others, preserve order. |
| `project-reorder` | Re-order the listed columns to the front; keep others. |
| `project-away` | **Exclude** the listed columns; keep everything else. |
| `project-keep` | Keep only the listed columns; opposite of `project-away`. |

```kql
DeviceProcessEvents
| project Time = Timestamp,
          Host = DeviceName,
          Cmd  = ProcessCommandLine,
          Hash = SHA256

DeviceProcessEvents
| project-away ReportId, MachineGroup, AdditionalFields

DeviceProcessEvents
| project-reorder DeviceName, AccountName, FileName    // these go first
```

> When a detection ends with `project`, **always** put `Timestamp`
> first and the high-value pivot columns (`DeviceName`, `AccountName`,
> `FileName`) before low-cardinality metadata. Analyst eyes scan
> left-to-right.
