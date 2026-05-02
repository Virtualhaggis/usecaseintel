# KQL anti-patterns — common mistakes & fixes

Patterns the BluRaven course flags as "not a detection, that's a
dashboard" or that produce silent false negatives at scale.

<!-- ============================================================== -->

## anti-bare-process-execution

**Smell**: filtering only on `FileName == "powershell.exe"` with no
parent / cmd-line / behaviour predicate.

```kql
// WRONG — fires on every legit PS launch
DeviceProcessEvents
| where FileName =~ "powershell.exe"

// RIGHT — pair with the suspicious context that turns it into intent
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName in~ ("outlook.exe","winword.exe","excel.exe")
   or ProcessCommandLine has_any ("-EncodedCommand","DownloadString","IEX","Invoke-Expression")
   or ProcessCommandLine matches regex @"-W(in)?(dow)?Style?\s+H(idden)?"
```

> Bare process execution as a detection produces 1000s of FPs/day in
> any real environment. The detection is the *combination*.

<!-- ============================================================== -->

## anti-no-time-bound

**Smell**: query runs against the full table without a `Timestamp >
ago(...)` predicate. Defender will throttle / OOM.

```kql
// WRONG
DeviceProcessEvents | where FileName == "powershell.exe"

// RIGHT
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
```

> Always-first: time bound. Indexes seek on `Timestamp` first.

<!-- ============================================================== -->

## anti-contains-instead-of-has

**Smell**: using `contains` for token-aligned text. Slower and can
miss because of leading/trailing whitespace inside.

```kql
// SLOWER — fragment match, fully scans the column
| where ProcessCommandLine contains "-EncodedCommand"

// FASTER — token-aligned, indexed
| where ProcessCommandLine has "-EncodedCommand"
```

> `has` is the Defender-recommended default unless you specifically
> need substring-without-token-boundary matching.

<!-- ============================================================== -->

## anti-case-sensitive-equality

**Smell**: matching binary names with `==`. Adversaries can rename
or use mixed case (`PowerShell.exe`, `POWERSHELL.EXE`).

```kql
// WRONG — misses PowerShell.exe / POWERSHELL.exe
| where FileName == "powershell.exe"

// RIGHT — case-insensitive
| where FileName =~ "powershell.exe"
```

> `=~` is case-insensitive equality. Same column-index access path,
> just folded.

<!-- ============================================================== -->

## anti-bad-account-filter

**Smell**: detection fires on every machine account / SYSTEM
context, drowning the SOC.

```kql
// Add to almost every endpoint detection
| where AccountName !endswith "$"     // exclude machine accounts
| where AccountName !in~ ("system","local service","network service")
```

<!-- ============================================================== -->

## anti-where-after-summarize

**Smell**: filtering on a computed column AFTER aggregation that
could've been pre-filtered to cut data 10x.

```kql
// SUBOPTIMAL — aggregates the whole table then filters
DeviceProcessEvents
| summarize Count = count() by AccountName, FileName
| where Count > 100

// BETTER — pre-filter the noisy/known-good first
DeviceProcessEvents
| where FileName !in~ ("svchost.exe","conhost.exe","cmd.exe")
| summarize Count = count() by AccountName, FileName
| where Count > 100
```

<!-- ============================================================== -->

## anti-flat-summarize-by-process

**Smell**: `summarize ... by ProcessCommandLine` — every unique
command line is its own bucket. Output explodes and behaviour signal
is lost.

```kql
// WRONG — explodes per unique cmd-line variation
| summarize count() by AccountName, ProcessCommandLine

// RIGHT — bucket on the binary, peek into cmd-lines
| summarize Count = count(),
            SampleCmd = any(ProcessCommandLine)
            by AccountName, FileName
```

<!-- ============================================================== -->

## anti-naive-trycloudflare-allowlist

**Smell**: blanket-trust a CDN domain (`*.trycloudflare.com`,
`*.workers.dev`, `*.web.app`) without realising adversaries abuse
the same domains for phishing / C2.

```kql
// WRONG
| where RemoteUrl !contains "trycloudflare.com"

// RIGHT — keep them in scope, flag the *first time* a host hits one
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1h))
    | where RemoteUrl endswith "trycloudflare.com"
    | summarize by RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteUrl endswith "trycloudflare.com"
| join kind=leftanti Baseline on RemoteUrl
```

<!-- ============================================================== -->

## anti-no-noise-cap

**Smell**: detection that has no `| top` / `| take` / `| summarize`
ceiling — fires per event, swamps the alerting pipeline.

```kql
// Add a per-time-bucket dedup if the alert is a repeating signal
| summarize First = min(Timestamp), Total = count(),
            arg_min(Timestamp, *)
            by DeviceName, AccountName, FileName
```

<!-- ============================================================== -->

## anti-ignoring-IsInitiatingProcessRemoteSession

**Smell**: missing context that the process was spawned via RDP /
WinRM. Often the differentiator between "user did this" vs "attacker
did this remotely".

```kql
| where IsInitiatingProcessRemoteSession == true   // pivot signal
```

<!-- ============================================================== -->

## anti-magic-numbers-without-comments

**Smell**: `> 25`, `< 5`, `between (3 and 12)` thresholds with no
comment. Reviewing analyst can't know why.

```kql
// WRONG
| where MailboxCount > 25

// RIGHT
| where MailboxCount > 25     // 25 = empirical inbox-rule fan-out
                              //      threshold from 90-day baseline
                              //      (P95 = 18, P99 = 27)
```

<!-- ============================================================== -->

## anti-single-table-when-correlation-needed

**Smell**: trying to express "user clicked link AND ran malware" with
a single `EmailEvents` query. Doesn't work — the malware lives in
`DeviceProcessEvents`.

> Course principle: one table per source of truth. Correlation lives
> in `join`s. If your detection should span the wire (`DeviceNetwork`)
> and the host (`DeviceProcess`), you need both tables.
