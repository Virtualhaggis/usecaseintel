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
This vulnerability allowed blocked users to interact freely with enterprise AI tools, despite explicit …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1213** — Data from Information Repositories
- **T1580** — Cloud Infrastructure Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Successful Amazon Quick/QuickSight chat-agent API invocations from non-console user agents

`UC_0_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as objects values(All_Changes.command) as actions from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command="*ChatAgent*" OR All_Changes.command="*ChatExperience*" OR All_Changes.command="InvokeAgent" OR All_Changes.command="GenerateAssistantResponse" OR All_Changes.command="StartChat*") All_Changes.status=success by All_Changes.user All_Changes.user_agent All_Changes.src All_Changes.dest All_Changes.action | `drop_dm_object_name(All_Changes)` | where NOT match(user_agent, "(?i)^(aws-internal|console\.amazonaws|signin\.aws\.amazon|quicksight-frontend|Mozilla)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### [LLM] Repeated post-patch AGENT_ACCESS_DENIED / 401 responses on Amazon Quick chat-agent calls by a single principal

`UC_0_4` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as actions values(All_Changes.user_agent) as agents from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" (All_Changes.command="*ChatAgent*" OR All_Changes.command="*ChatExperience*" OR All_Changes.command="InvokeAgent" OR All_Changes.command="GenerateAssistantResponse" OR All_Changes.command="StartChat*") (All_Changes.status=failure OR All_Changes.result="AccessDenied*" OR All_Changes.result="AGENT_ACCESS_DENIED" OR All_Changes.result="UnauthorizedOperation") by All_Changes.user All_Changes.src _time span=10m | `drop_dm_object_name(All_Changes)` | where count >= 5 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
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

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
