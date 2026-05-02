# Annotated full-query examples

End-to-end detections that demonstrate combining multiple patterns
correctly. Used as few-shot anchors when the LLM generates new
detections — they show the *shape* of "good".

<!-- ============================================================== -->

## example-phishing-link-to-process-execution

**Scenario**: user clicks a phishing link, the click correlates within
60 seconds to a non-browser child process (PowerShell, mshta, rundll32,
etc.) on the same device.

**Why this is high-fidelity**: 99% of clicks lead nowhere. The narrow
time window + non-browser child eliminates the noise.

```kql
let LookbackDays = 7d;
let CorrelationWindowSec = 60;
// 1. Inbound delivered email with a clickable URL
let SuspectEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
        and DeliveryAction == "Delivered"
    | join kind=inner (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTime = Timestamp, Url, UrlDomain;
// 2. Click on that URL
let SuspectClicks = SuspectEmails
    | join kind=inner (
        UrlClickEvents
        | where Timestamp > ago(LookbackDays)
        | where ActionType in ("ClickAllowed","ClickedThrough")
        | project NetworkMessageId, ClickTime = Timestamp,
                  AccountUpn, IPAddress
      ) on NetworkMessageId;
// 3. Non-browser child process within 60s on the recipient's device
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~
    ("chrome.exe","msedge.exe","firefox.exe","brave.exe","arc.exe","outlook.exe")
| where FileName in~
    ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe",
     "regsvr32.exe","wscript.exe","cscript.exe","bitsadmin.exe",
     "certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + CorrelationWindowSec * 1s)
| project DeviceName, AccountName,
          ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          SenderFromAddress, Subject, Url,
          ChildProcess = FileName, ChildCmd = ProcessCommandLine
| order by ClickTime desc
```

**Tier**: alerting · **FP rate**: low

<!-- ============================================================== -->

## example-lateral-movement-via-psexec

**Scenario**: PsExec-style admin tool run from a host that wasn't seen
running it during the 30-day baseline.

```kql
let BaselineDays = 30d;
let RecentHours = 4h;
let PsExecBins = dynamic(["psexec.exe","psexec64.exe","paexec.exe","csexec.exe","remcom.exe"]);
let PsExecBaseline = DeviceProcessEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | where FileName in~ (PsExecBins)
    | summarize by DeviceName;     // hosts that legitimately run PsExec
DeviceProcessEvents
| where Timestamp > ago(RecentHours)
| where FileName in~ (PsExecBins)
| where AccountName !endswith "$"
| join kind=leftanti PsExecBaseline on DeviceName
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, InitiatingProcessFileName,
          IsInitiatingProcessRemoteSession
| order by Timestamp desc
```

**Tier**: alerting · **FP rate**: low (after initial baseline ramp-up)

<!-- ============================================================== -->

## example-aad-impossible-travel

**Scenario**: same user successfully signs in from two countries
within 60 minutes — physical impossibility absent VPN abuse.

```kql
let WindowMinutes = 60;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0                    // successful auth only
| where isnotempty(Country)
| project Timestamp, AccountUpn, Country, City, IPAddress, Application
| order by AccountUpn asc, Timestamp asc
| extend PrevCountry = prev(Country),
         PrevCity = prev(City),
         PrevTime = prev(Timestamp),
         PrevAccount = prev(AccountUpn)
| where AccountUpn == PrevAccount
   and Country != PrevCountry
   and datetime_diff('minute', Timestamp, PrevTime) <= WindowMinutes
| project AccountUpn,
          From = PrevCountry, FromTime = PrevTime,
          To = Country, ToTime = Timestamp,
          MinutesDelta = datetime_diff('minute', Timestamp, PrevTime),
          IPAddress, Application
| order by ToTime desc
```

**Tier**: alerting · **FP rate**: medium (corporate VPNs / road warriors)

<!-- ============================================================== -->

## example-shadow-copy-deletion-prelude-to-ransomware

**Scenario**: Volume Shadow Copy deletion via vssadmin, wmic, or
PowerShell — common pre-encryption step in ransomware.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName in~ ("powershell.exe","pwsh.exe")
       and ProcessCommandLine has_any ("Get-WmiObject Win32_Shadowcopy",
                                        "Remove-WmiObject Win32_Shadowcopy"))
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Tier**: alerting · **FP rate**: very low (legit shadow-copy lifecycle is rare in user space)

<!-- ============================================================== -->

## example-aad-app-consent-grant

**Scenario**: a user consents to a third-party AAD app (illicit
consent attack — pre-cursor to OAuth-token theft). Catch via
identity sign-in events for the app.

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where Application !in~ (
    "Microsoft Authenticator", "Office 365", "Microsoft Office",
    "Microsoft Teams", "Microsoft Edge", "Outlook"
  )
| where ResourceId == "00000003-0000-0000-c000-000000000000"   // Microsoft Graph
| where ErrorCode == 0
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            UserCount = dcount(AccountUpn)
            by Application, ApplicationId
| where FirstSeen > ago(2h)            // brand-new app
| order by FirstSeen desc
```

**Tier**: hunting · **FP rate**: medium (legit SaaS adoption)

<!-- ============================================================== -->

## example-rare-process-via-process-tree-anti-baseline

**Scenario**: a binary spawned by a parent that has never spawned it
before in the 30-day baseline. Generic but powerful behavioural
signal.

```kql
let BaselineDays = 30d;
let RecentHours = 4h;
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | summarize by InitiatingProcessFileName, FileName;
DeviceProcessEvents
| where Timestamp > ago(RecentHours)
| where AccountName !endswith "$"
| where FileName !in~ ("conhost.exe","svchost.exe","backgroundtaskhost.exe",
                       "wermgr.exe","wuauclt.exe","searchindexer.exe")
| join kind=leftanti Baseline on InitiatingProcessFileName, FileName
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine
| order by Timestamp desc
```

**Tier**: hunting · **FP rate**: high day 1, drops to medium after a
30-day warmup (because the baseline matures).
