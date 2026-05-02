# KQL query patterns — reusable shapes

Each entry is keyed `pattern-<slug>` so the prompt can request specific
anchors. Patterns are language-agnostic (don't hard-code one specific
TTP) — the per-actor / per-article generator fills in the variable
parts.

<!-- ============================================================== -->

## pattern-process-tree

**Goal**: surface a child process spawned by a specific parent, with
both processes' command lines and the time delta between them.

**Why this matters**: most "high-fidelity" detections are joins on the
parent/child relationship. The parent narrows scope (e.g. `outlook.exe`
spawning), the child narrows behaviour (e.g. `powershell.exe`).

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "outlook.exe"     // parent — change per detection
| where FileName has_any ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

> Course principle: a parent-process predicate without a child-process
> predicate is a dashboard, not a detection. Always pair them.

<!-- ============================================================== -->

## pattern-time-window-correlation

**Goal**: tie two events on the same host within a small window. e.g.
"phishing-link click ≤60s before non-browser child of browser".

```kql
let LookbackDays = 7d;
let WindowSeconds = 60;
let Suspicious = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("ClickAllowed","ClickedThrough");
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe")
| join kind=inner Suspicious on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTimestamp .. ClickTimestamp + WindowSeconds * 1s)
| project ClickTimestamp, ProcessTimestamp = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTimestamp),
          DeviceName, AccountName,
          Url, ProcessCommandLine, FileName
| order by ClickTimestamp desc
```

> Course principle: time-window joins eliminate the 99% of clicks that
> don't lead anywhere — they're the single biggest noise reducer.

<!-- ============================================================== -->

## pattern-behavioural-baseline

**Goal**: detect deviation from per-user / per-host norms. Use
`summarize` over a baseline window then compare to a recent window.

```kql
let BaselineDays = 30d;
let RecentHours = 4h;
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | summarize BaselineCount = count() by AccountName, FileName
    | where BaselineCount > 5;     // strip per-user one-offs
DeviceProcessEvents
| where Timestamp > ago(RecentHours)
| where FileName == "powershell.exe"
| join kind=leftanti Baseline on AccountName, FileName
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

> Course principle: anti-joins against a baseline are the cleanest way
> to express "first-time observed" — no machine learning needed.

<!-- ============================================================== -->

## pattern-cmdline-decode

**Goal**: PowerShell `-EncodedCommand` and base64 are common defender
evasion. Decode them inline.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-EC ")
| extend B64 = extract(@"(?i)(?:-(?:e(?:nc(?:odedcommand)?)?))\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(B64)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, B64, Decoded
| order by Timestamp desc
```

> Note: `base64_decode_tostring` returns a UTF-16-LE string for
> PowerShell payloads — re-decode if you see the typical `\u0000`
> separators.

<!-- ============================================================== -->

## pattern-rare-domain-by-org

**Goal**: a host contacts a domain that's never been seen anywhere
in the org during the baseline period.

```kql
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1h))
    | summarize BaselineHosts = dcount(DeviceName) by RemoteUrl
    | where BaselineHosts > 2;
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where isnotempty(RemoteUrl)
| join kind=leftanti Baseline on RemoteUrl
| summarize FirstSeen = min(Timestamp), HostsCount = dcount(DeviceName)
            by RemoteUrl
| where HostsCount >= 1
| order by FirstSeen desc
```

<!-- ============================================================== -->

## pattern-credential-access-fan-out

**Goal**: one user / one host accessing N distinct mailboxes (or N
distinct AAD apps) within a short window — classic post-auth account
takeover signal.

```kql
let WindowMinutes = 10m;
EmailEvents
| where Timestamp > ago(7d)
| summarize MailboxCount = dcount(RecipientEmailAddress)
            by SenderObjectId, bin(Timestamp, WindowMinutes)
| where MailboxCount > 25
| order by Timestamp desc
```

<!-- ============================================================== -->

## pattern-lolbin-network-egress

**Goal**: living-off-the-land binaries (LOLBins) that legitimately
exist on Windows but are abused by adversaries to reach the internet.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe",
    "rundll32.exe","msbuild.exe","installutil.exe","wmic.exe",
    "wscript.exe","cscript.exe","cmstp.exe","forfiles.exe",
    "ftp.exe","tftp.exe","odbcconf.exe"
  )
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

> Course principle: LOLBin + public destination is a high-signal pair.
> LOLBin alone is noise; public alone is internet usage.
