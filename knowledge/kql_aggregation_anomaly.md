# KQL aggregation, time travel & anomaly detection

Distilled from BluRaven *Advanced Hands-On KQL* — Sections 8 (External
Threat Intel Feeds), 9 (Time Traveling), 10 (Aggregating Data), 11
(Visualizing Data), 12 (Rapid Triage), and 13 (Anomaly Detection).
This file consolidates the detection-engineering toolkit beyond
basic filtering and joining.

<!-- ============================================================== -->

## externaldata-tii-feeds

The `externaldata` operator pulls a remote file (CSV/TXT/JSON) into
KQL as a tabular expression. The single most useful pattern in this
knowledge base — letting you drop a hosted blocklist into a join and
have it apply org-wide on the next run.

```kql
// CSV without header — list of IPs in a .txt
let MaliciousIPs = externaldata (IPAddress:string)
    [@"https://raw.githubusercontent.com/example/iocs/main/ips.txt"];

DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (MaliciousIPs | project IPAddress)

// CSV with header
externaldata (IOC:string, Type:string, Source:string)
    [@"https://example.com/iocs.csv"]
    with (format="csv", ignoreFirstRecord=true)

// JSON
externaldata (Indicators:dynamic)
    [@"https://example.com/iocs.json"]
    with (format="multijson")
```

### Tips

- **Hosting**: GitHub raw, Azure Blob, S3 (public-readable), any HTTPS.
- **Caching**: Defender caches the response — don't expect the file to
  re-download on every query within a short window.
- **Schema**: must match the file. Mismatched columns silently fail.
- **Verbatim string** (`@"..."`) for the URL avoids any escaping
  surprises with `?` or `&` in query strings.

<!-- ============================================================== -->

## time-travel-historical-investigation

When you're investigating a past incident and want to keep using
`now()` / `ago()` semantics, redefine the engine's notion of "now"
with three `set` statements.

```kql
// Make the engine pretend it is 2026-04-25 14:10:00 UTC
set query_datetimescope_column = "TimeGenerated";   // or "Timestamp"
set query_datetimescope_to     = datetime(2026-04-25 23:59:00);
set query_now                  = datetime(2026-04-25 14:10:00);

// Now `ago(1h)` means "1h before 14:10:00 on 2026-04-25"
SecurityEvent
| where TimeGenerated between (now(-1h) .. now(+1h))
| where EventID in (4624, 4625)
| where TargetUserName =~ "adm-roy.trenneman"
```

> Course value: instead of writing
> `between(datetime(2026-04-25 13:10) .. datetime(2026-04-25 15:10))`
> in 12 different places when iterating, you redefine `now` once and
> the rest of the query reads naturally.

> M365 Defender — column is `Timestamp`. Sentinel — column is
> `TimeGenerated`. Set `query_datetimescope_column` accordingly.

<!-- ============================================================== -->

## aggregation-summarize-essentials

`summarize` is the workhorse — every detection that says "more than N"
or "first time today" passes through it.

| Function | Purpose |
|----------|---------|
| `count()` | Row count. Default column name is `count_`. |
| `dcount(col)` | Distinct count (probabilistic — fast, ~ ±2% accurate). |
| `count_distinct(col)` | Exact distinct count. Slower than `dcount`. |
| `sum(col)` / `avg(col)` / `min(col)` / `max(col)` | Numeric aggregations. |
| `arg_min(col, *)` / `arg_max(col, *)` | **Whole-row picker** — first/last row by `col`. Use `*` to keep all columns. |
| `make_list(col, MaxSize)` | Array of all non-null values per group. Default cap 1,048,576. |
| `make_set(col)` | Like `make_list` but deduplicated. |
| `percentile(col, n)` | Approx percentile — `percentile(Bytes, 99)`. |
| `percentiles(col, p1, p2, ...)` | Multiple percentiles in one shot. |

### Conditional aggregation — `*if` family

Avoid running multiple summarize passes; conditional aggregation
counts only matching rows.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| summarize
    SuccessfulConnections = countif(ActionType == "ConnectionSuccess"),
    FailedConnections     = countif(ActionType == "ConnectionFailed"),
    UniqueRemoteIPs       = dcountif(RemoteIP, ActionType == "ConnectionSuccess"),
    SampleFailedRemoteIPs = make_setif(RemoteIP, ActionType == "ConnectionFailed")
    by DeviceName
```

Available `*if` variants: `countif`, `dcountif`, `sumif`, `avgif`,
`minif`, `maxif`, `make_listif`, `make_setif`.

### `arg_max` / `arg_min` — last-seen detection lifeline

```kql
// One row per user — the most recent successful logon row, with all
// columns from THAT row (timestamp, IP, host, etc.)
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| summarize arg_max(TimeGenerated, *) by TargetUserName
```

<!-- ============================================================== -->

## aggregation-multi-valued-data

Some columns hold arrays — `AlertInfo.AttackTechniques`, AAD
`MfaDetail.AuthMethod` lists, etc. Use `mv-expand` to fan out one row
per element.

```kql
AlertInfo
| where Timestamp > ago(7d)
| mv-expand todynamic(AttackTechniques)     // wrap if column is string
| extend Technique = tostring(AttackTechniques)
| summarize Count = count() by Technique
```

> Common gotcha: if `mv-expand` errors with *"expanded expression
> expected to have dynamic type"*, the column is typed `string` and
> needs `todynamic(...)` first.

`mv-apply` is the heavier-weight cousin — applies a sub-query to
each array element. Reach for it when you need to filter elements
before fanning out.

<!-- ============================================================== -->

## visualisation-render

Visualisations live on the right side of a `summarize` — you give the
engine a numeric series + a category and ask it to draw.

```kql
T | render <kind> [with (option=value, ...)]
```

| Kind | Use for |
|------|---------|
| `timechart` | Series over time — most common security viz. |
| `columnchart` / `barchart` | Categorical comparisons. |
| `piechart` | Share-of-total. Use sparingly; analysts dislike them. |
| `scatterchart` | Relationship between two numerics. |
| `linechart` | Multiple time series overlaid. |
| `areachart` | Stacked time series. |
| `card` | Single-value KPI tile. |
| `map` | Geospatial — needs `Longitude` and `Latitude` columns. |

### Useful options

```kql
| render timechart with (
    title="Failed logons per device",
    xtitle="Time",
    ytitle="Failed logons",
    ysplit=panels,             // separate panel per category
    legend=hidden
)
```

> Course practice: time-bin first, summarise, *then* render.
> ```
> | summarize count() by bin(Timestamp, 1h), DeviceName
> | render timechart
> ```

<!-- ============================================================== -->

## triage-alert-context-query

The Section-12 "alert context" pattern: one query that summarises
everything an analyst wants to know about a recurring alert, by
title, using conditional aggregation against `AlertEvidence`.

```kql
AlertEvidence
| where ServiceSource == "Microsoft Defender for Endpoint"
| extend NewProcess = iif(EntityType == "Process",
                          tostring(extract_json('$.ParentProcess.FriendlyName',
                                                 tostring(AdditionalFields))),
                          "")
| summarize
    Count             = count(),
    FirstTriggered    = min(Timestamp),
    LastTriggered     = max(Timestamp),
    DeviceCount       = dcount(DeviceId),
    Devices           = make_set_if(DeviceName, EntityType == "Machine"),
    UserCount         = dcountif(AccountName, EntityType == "User"),
    Users             = make_set_if(strcat(AccountDomain, "\\", AccountName),
                                    EntityType == "User"),
    FileCount         = countif(EntityType == "File"),
    UniqueFileCount   = dcountif(FileName, EntityType == "File"),
    Files             = make_set_if(FileName, EntityType == "File"),
    ProcessCount      = countif(EntityType == "Process"),
    UniqueProcessCount = dcountif(FileName, EntityType == "Process"),
    Processes         = make_set_if(FileName, EntityType == "Process"),
    UniqueCmdLines    = make_set_if(ProcessCommandLine, EntityType == "Process"),
    UrlCount          = countif(EntityType == "Url"),
    Urls              = make_set_if(RemoteUrl, EntityType == "Url"),
    IPCount           = countif(EntityType == "Ip"),
    IPs               = make_set_if(RemoteIP, EntityType == "Ip"),
    RegistryKeys      = make_set_if(RegistryKey,
                                    EntityType == "RegistryKey" and isnotempty(RegistryKey))
    by Title
```

> Course principle: the *Title* is the same for every alert raised by
> the same detection rule. Aggregating by title gives you a per-rule
> health view: which rules fire most, on which hosts, with what
> entities, and how unique those entities are.

<!-- ============================================================== -->

## anomaly-static-vs-dynamic

| Approach | Threshold | Use when |
|----------|-----------|----------|
| **Static** | Hard-coded (`> 100 logons/day`) | Smaller estate, well-understood baseline. |
| **Dynamic** | Computed at query time (twice the user's 5-day average) | Large/dynamic estate; reduces FP/alert fatigue. |

### Static example

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| summarize LoginCount = count() by TargetUserName
| where LoginCount > 100
```

### Dynamic — Windows-10-only first-execution detection

```kql
let win10_devices =
    DeviceInfo
    | where OSPlatform == 'Windows10'
    | summarize make_set(DeviceName);

DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName in (win10_devices)
| where FileName =~ 'sethc.exe'
```

### Dynamic — moving-average comparison (login burst detection)

```kql
let lookback     = 8d;
let recent_window = 1d;

let baseline =
    SecurityEvent
    | where TimeGenerated between (ago(lookback) .. ago(recent_window))
    | where EventID == 4624
    | where toint(format_timespan(dayofweek(TimeGenerated), 'd')) !in (6, 7)   // weekdays only
    | summarize avg_login_count = (count() / 5.0) by TargetUserName;

SecurityEvent
| where TimeGenerated > ago(recent_window)
| where EventID == 4624
| summarize current_count = count() by TargetUserName
| join kind=inner baseline on TargetUserName
| where current_count >= 2 * avg_login_count
| where current_count > 5      // suppression for low-volume users
```

<!-- ============================================================== -->

## anomaly-frequency-analysis

Frequency analysis = "rare = suspicious". Effective for binaries,
domains, hashes, parent-child pairs.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize DeviceCount = dcount(DeviceId),
            FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            SampleCmd   = any(ProcessCommandLine)
            by FileName
| where DeviceCount <= 2                      // observed on ≤2 devices
| order by DeviceCount asc, FirstSeen desc
```

> Course principle: count entities (`dcount(DeviceId)`), not events
> (`count()`). One device running malware 1,000 times is one device,
> not 1,000 alerts.

<!-- ============================================================== -->

## anomaly-time-series-binning

Binning + threshold catches sudden spikes:

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| summarize Connections = count() by bin(Timestamp, 1h), DeviceName
| where Connections > 1000        // static threshold per hour
| order by Connections desc
```

For week-over-week shape comparison, use `make-series`:

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIPType == "Public"
| make-series Connections = count()
    default = 0
    on Timestamp from ago(14d) to now() step 1h
    by DeviceName
```

The `default = 0` is critical — without it, hours with zero rows just
disappear from the series, and downstream analysis silently mis-aligns.

<!-- ============================================================== -->

## anomaly-series-decompose

`series_decompose_anomalies()` separates a time series into trend,
seasonal, and residual components, scoring each point's deviation
from expectation. The default works for most security workloads.

```kql
DeviceLogonEvents
| where Timestamp > ago(14d)
| where ActionType == "LogonSuccess"
| make-series LogonCount = count()
    default = 0
    on Timestamp from ago(14d) to now() step 1h
    by DeviceName
| extend (Anomalies, Score, Baseline) = series_decompose_anomalies(LogonCount, 1.5)
| where Anomalies has "1" or Anomalies has "-1"
| project DeviceName, Timestamp, LogonCount, Anomalies, Score, Baseline
| render anomalychart with (anomalycolumns=Anomalies)
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `Threshold` | 1.5 | Higher = fewer anomalies flagged. |
| `Seasonality` | autodetect | Specific period in seconds, or `none`, or `-1` autodetect. |
| `Trend` | `'avg'` | `'avg'`, `'linefit'`, or `'none'`. |
| `TestPoints` | 0 | Points at the end to *exclude* from learning (forecasting). |

> Course caveat: there is no one-size-fits-all anomaly detector.
> `series_decompose_anomalies` is a great default but a poor fit for
> bursty, low-volume, or highly seasonal-with-events signals. Always
> baseline FP rate against a known-clean week before alerting on it.
