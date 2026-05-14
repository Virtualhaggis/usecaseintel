# [CRIT] Amazon Quick Bug Exposed AI Chat Agents to Users Blocked by Custom Permissions

**Source:** Cyber Security News
**Published:** 2026-05-14
**Article:** https://cybersecuritynews.com/amazon-quick-bug-exposed-ai-chat-agents/

## Threat Profile

Home Cyber Security News 
Amazon Quick Bug Exposed AI Chat Agents to Users Blocked by Custom Permissions 
By Abinaya 
May 14, 2026 
Imagine locking your organization’s sensitive data behind a heavy vault door, only to realize the locking mechanism is entirely missing.
Security researchers at Fog Security recently uncovered a severe authorization bypass in Amazon Quick’s AI Chat Agents.
This vulnerability allowed blocked users to interact freely with enterprise AI tools, despite explicit administ…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1530** — Data from Cloud Storage
- **T1213** — Data from Information Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Amazon Quick Chat Agent API – AGENT_ACCESS_DENIED denial hunt (post-CWE-862 patch audit)

`UC_12_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`cim_Change_indexes` sourcetype=aws:cloudtrail eventSource="quicksight.amazonaws.com" (errorCode="AGENT_ACCESS_DENIED" OR errorMessage="*AGENT_ACCESS_DENIED*" OR (errorCode="AccessDeniedException" AND errorMessage="*AGENT_ACCESS_DENIED*")) (eventName=*Chat* OR eventName=*Agent* OR eventName=*Topic* OR eventName=*Q* OR requestParameters.*=*ChatAgent*)
| eval AwsAccount=coalesce('recipientAccountId','userIdentity.accountId'), Principal=coalesce('userIdentity.userName','userIdentity.sessionContext.sessionIssuer.userName','userIdentity.arn'), SrcIP='sourceIPAddress'
| stats min(_time) as firstDeny max(_time) as lastDeny count as deniedCalls values(eventName) as actions values(userAgent) as userAgents values(SrcIP) as sourceIPs dc(eventName) as distinctActions by AwsAccount, Principal
| where firstDeny >= relative_time(now(), "-90d@d")
| convert ctime(firstDeny) ctime(lastDeny)
| sort - deniedCalls
```

**Defender KQL:**
```kql
// Defender for Cloud Apps CloudAppEvents — AWS connector ships QuickSight/Quick activity here
CloudAppEvents
| where Timestamp > ago(90d)
| where Application has_any ("Amazon Web Services", "AWS", "QuickSight", "Amazon Quick")
| where ActionType has_any ("Chat", "Agent", "Topic", "Q") or tostring(RawEventData) has_any ("ChatAgent", "chatAgent")
| extend ErrorCode = tostring(parse_json(tostring(RawEventData)).errorCode),
         ErrorMessage = tostring(parse_json(tostring(RawEventData)).errorMessage),
         EventSource = tostring(parse_json(tostring(RawEventData)).eventSource),
         AwsAccountId = tostring(parse_json(tostring(RawEventData)).recipientAccountId),
         SrcIp = tostring(parse_json(tostring(RawEventData)).sourceIPAddress),
         UA = tostring(parse_json(tostring(RawEventData)).userAgent)
| where EventSource =~ "quicksight.amazonaws.com"
| where ErrorCode == "AGENT_ACCESS_DENIED"
    or ErrorMessage has "AGENT_ACCESS_DENIED"
    or (ErrorCode =~ "AccessDeniedException" and ErrorMessage has "AGENT_ACCESS_DENIED")
| summarize FirstDeny = min(Timestamp),
            LastDeny  = max(Timestamp),
            DeniedCalls = count(),
            Actions   = make_set(ActionType, 25),
            SourceIPs = make_set(SrcIp, 25),
            UserAgents = make_set(UA, 10)
            by AwsAccountId, AccountObjectId, AccountDisplayName
| order by DeniedCalls desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33017`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
