# KQL combining data — `union`, `join`, and which kind to pick

Distilled from BluRaven *Advanced Hands-On KQL* — Sections 6
(Combining Data Sets) + 7 (Joining Datasets). The choice between
`union` and the various `join` kinds is the highest-leverage decision
in any cross-source detection.

<!-- ============================================================== -->

## combine-decision-tree

| Question | Operator |
|----------|----------|
| Append rows from N tables, same shape — same logical event source split across schemas | `union` |
| Enrich left with right — keep left rows whether or not match exists | `join kind=leftouter` |
| Correlate two events that *must both* exist (e.g. click + process spawn) | `join kind=inner` |
| Filter left to "rows that have a match in right" — don't need right's columns | `join kind=leftsemi` |
| Filter left to "rows that have NO match in right" — anti-baseline / first-time-seen | `join kind=leftanti` |
| Show all from both, with NULLs where unmatched (rare, mostly debugging) | `join kind=fullouter` |

> Course warning: `join` with no `kind=` defaults to **`innerunique`**,
> which silently de-duplicates the left side on the join key. This
> almost never matches what a security analyst means. **Always specify
> `kind=` explicitly.**

<!-- ============================================================== -->

## combine-union-operator

```kql
// Two forms of the same operation
<Table1> | union <Table2>, <Table3>
union <Table1>, <Table2>, <Table3>

// Wildcards on table names
union (DeviceProcess*), (DeviceFile*)
```

### Optional parameters

| Parameter | Effect |
|-----------|--------|
| `kind=outer` (default) | All columns kept; unmatched columns filled with null. |
| `kind=inner` | Only columns common to all participating tables. |
| `withsource=ColName` | Add a `ColName` column tagging each row with its source table — invaluable for cross-source debugging. |
| `isfuzzy=true` | If a referenced table is missing/inaccessible, skip it and continue. Default `false` (whole query fails). |

### Pre-filter, *then* union — never the other way

```kql
// SLOW — combines all data, then filters
union isfuzzy=true DeviceProcessEvents, DeviceEvents
| where Timestamp > ago(5d)
| where AccountName =~ "alex.wilber"

// FAST — each table filters before the union runs
union isfuzzy=true
    ( DeviceProcessEvents
        | where Timestamp > ago(5d)
        | where AccountName =~ "alex.wilber" ),
    ( DeviceEvents
        | where Timestamp > ago(5d)
        | where AccountName =~ "alex.wilber" )
```

> Course principle: every `union` over Defender tables should
> pre-filter the time window inside each subquery. The engine cannot
> push predicates across a `union`, so anything outside the parens
> runs after the merge.

<!-- ============================================================== -->

## combine-join-operator-syntax

```kql
<LeftTable>
| join [kind=<JoinType>] [<Hints>] <RightTable> on <JoinConditions>

// Single column
| join kind=inner Right on $left.ColumnName == $right.ColumnName

// Multiple columns (AND-combined)
| join kind=inner Right on $left.A == $right.A and $left.B == $right.B

// Same-named columns shorthand
| join kind=inner Right on CommonCol1, CommonCol2

// Mixed
| join kind=inner Right on CommonCol, $left.X == $right.Y
```

When both sides have a column with the same name, the right-side
column is auto-renamed with a `1` suffix (e.g. `UserId1`,
`UserName1`). Reach for `project-away` to drop the duplicates after
joining:

```kql
UserLoginEvents
| join kind=leftouter UserProfiles on UserId
| project-away UserId1, UserName1
```

<!-- ============================================================== -->

## combine-join-kinds-reference

| `kind=` | Left rows kept | Right rows kept | Right cols in output | Use case |
|---------|----------------|-----------------|----------------------|----------|
| `inner` | matching only | matching only | yes | "both events happened" — phishing click + child process |
| `leftouter` | all | matching only | yes (NULL when no match) | enrich left rows; keep unmatched |
| `rightouter` | matching only | all | yes (NULL when no match) | rarely useful — flip arguments and use `leftouter` |
| `fullouter` | all | all | yes (NULL on either side) | debug / reconciliation |
| `leftsemi` | matching only | none | **no** | "left rows where a match exists" — fastest if right cols not needed |
| `rightsemi` | none | matching only | only right | "right rows that match left" — pivots roles |
| `leftanti` | non-matching only | none | no | **first-time-seen / not-in-baseline** — the workhorse for behavioural detection |
| `rightanti` | none | non-matching only | only right | "right rows with no left match" — uncommon |
| `innerunique` (**default**) | de-duplicated left | matching only | yes | **avoid** — leads to silent row loss |

### Anti-join — the detection engineer's favourite

```kql
// Process binaries that have NEVER been seen executed by this parent
// process during the 30-day baseline window
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(30d) .. ago(4h))
    | summarize by InitiatingProcessFileName, FileName;

DeviceProcessEvents
| where Timestamp > ago(4h)
| join kind=leftanti Baseline on InitiatingProcessFileName, FileName
```

### Inner join — the time-window correlation pattern

```kql
// Phishing click followed by non-browser child process within 60s
let LookbackDays = 7d;
let WindowSec = 60;
let Clicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project NetworkMessageId, ClickTime = Timestamp, AccountUpn;

DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~
    ("chrome.exe","msedge.exe","firefox.exe","brave.exe","outlook.exe")
| where FileName in~
    ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe")
| join kind=inner Clicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + WindowSec * 1s)
```

<!-- ============================================================== -->

## combine-join-performance

> **Smaller table on the LEFT.** Kusto streams the left side and
> builds a hash table for the right. If the right side is huge, the
> engine has to materialise it — slow. Filter both sides aggressively
> *before* the join, and put the smaller filtered set on the left.

```kql
// Use let-bindings to make filtering visible and reusable
let SmallSet = EmailEvents
    | where Timestamp > ago(7d)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress;

let BigSetFiltered = UrlClickEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project NetworkMessageId, ClickTime = Timestamp, AccountUpn;

SmallSet
| join kind=inner BigSetFiltered on NetworkMessageId
```

### Hints (advanced)

| Hint | Effect |
|------|--------|
| `hint.strategy=broadcast` | Ship the right table to every node — good when right is small (<100k rows). |
| `hint.strategy=shuffle` | Re-distribute by join key — good when both sides are large. |
| `hint.shufflekey=Col` | Shuffle on a specific column. |

These rarely need to be specified for hand-written detections — the
optimiser usually picks well. Reach for them when a join times out at
scale.
