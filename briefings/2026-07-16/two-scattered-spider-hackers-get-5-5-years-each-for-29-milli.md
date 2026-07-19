# [HIGH] Two Scattered Spider Hackers Get 5.5 Years Each for £29 Million TfL Hack

**Source:** The Hacker News
**Published:** 2026-07-16
**Article:** https://thehackernews.com/2026/07/two-scattered-spider-hackers-get-55.html

## Threat Profile

Two Scattered Spider Hackers Get 5.5 Years Each for £29 Million TfL Hack 
 Swati Khandelwal  Jul 16, 2026 Cybercrime / Identity Security 
Owen Flowers , 18, and Thalha Jubair , 20, were each sentenced to five and a half years at Woolwich Crown Court on Thursday, 16 July 2026, for the 2024 hack of Transport for London.
The attack left 148 TfL systems inoperable and forced all 27,000 of the transport authority's employees into an office to get their passwords reset in person. Both the NCA and th…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1098.005** — Account Manipulation: Device Registration
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Adversary MFA method registration within 1h of a password reset (Scattered Spider / ShinyHunters ATO)

`UC_37_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="o365:management:activity" Workload=AzureActiveDirectory (Operation="Reset user password" OR Operation="Change user password" OR Operation="Reset password (by admin)" OR Operation="Self-service password reset flow activity progress" OR Operation="User registered security info" OR Operation="User registered all required security info" OR Operation="Admin registered security info")
| eval target=coalesce(ObjectId,UserId)
| eval resetTime=if(match(Operation,"(?i)password"), _time, null())
| eval regTime=if(match(Operation,"(?i)registered security info"), _time, null())
| stats min(resetTime) as resetTime max(regTime) as regTime values(Operation) as ops values(ClientIP) as clientIPs by target
| where isnotnull(resetTime) AND isnotnull(regTime) AND regTime>=resetTime AND (regTime-resetTime)<=3600
| eval DeltaMin=round((regTime-resetTime)/60,1)
| convert ctime(resetTime) ctime(regTime)
| table target ops clientIPs resetTime regTime DeltaMin
| sort - regTime
```

**Defender KQL:**
```kql
let window = 1h;
let resets = CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("Reset user password","Change user password","Reset password")
| project ResetTime = Timestamp, AccountObjectId, AccountDisplayName, ResetIp = IPAddress, ResetAction = ActionType;
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("registered security info","registered all required security info")
| join kind=inner resets on AccountObjectId
| where Timestamp between (ResetTime .. ResetTime + window)
| project ResetTime, RegTime = Timestamp,
          DeltaMin = datetime_diff('minute', Timestamp, ResetTime),
          AccountDisplayName, AccountObjectId, ResetAction, ResetIp, RegIp = IPAddress
| order by RegTime desc
```

### MFA device registered from an IP never seen for the user (attacker enrollment for persistence)

`UC_37_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="o365:management:activity" Workload=AzureActiveDirectory (Operation="User registered security info" OR Operation="User registered all required security info")
| eval target=coalesce(ObjectId,UserId)
| join type=left target [
    search sourcetype="o365:management:activity" Workload=AzureActiveDirectory Operation="UserLoggedIn" earliest=-30d latest=-1d
    | eval target=coalesce(ObjectId,UserId)
    | stats values(ClientIP) as baselineIPs by target ]
| eval isNewIP=if(isnull(mvfind(baselineIPs, ClientIP)),1,0)
| where isNewIP=1
| iplocation ClientIP
| table _time target Operation ClientIP City Country
| sort - _time
```

**Defender KQL:**
```kql
let lookback = 30d;
let recent = 1d;
let baselineIPs = AADSignInEventsBeta
| where Timestamp between (ago(lookback) .. ago(recent))
| where ErrorCode == 0
| summarize by AccountObjectId, IPAddress;
CloudAppEvents
| where Timestamp > ago(recent)
| where ActionType has_any ("registered security info","registered all required security info")
| where isnotempty(IPAddress) and isnotempty(AccountObjectId)
| join kind=leftanti baselineIPs on AccountObjectId, IPAddress
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, IPAddress, CountryCode, ISP
| order by Timestamp desc
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
