# [CRIT] How a Malicious Google Skill on ClawHub Tricks Users Into Installing Malware

**Source:** Snyk
**Published:** 2026-02-10
**Article:** https://snyk.io/blog/clawhub-malicious-google-skill-openclaw-malware/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
February 10, 2026
0 mins read You ask your OpenClaw agent to "check my Gmail." It replies, "I need to install the Google Services Action skill first. Shall I proceed?" You say yes. The agent downloads the skill from ClawHub. It reads the instructions. Then, it pauses.
"This skill requires the 'openclaw-core' utility to function," the agent reports, displaying a helpful download link from the skill's README. "Please run this installer to continue."
…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `setup-service.com`
- **Domain (defanged):** `rentry.co/openclaw-core`
- **Domain (defanged):** `github.com/denboss99/openclaw-core`
- **Domain (defanged):** `github.com/aztr0nutz/NET_NINJA.v1.2`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1053.005** — Scheduled Task
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1204.002** — User Execution: Malicious File
- **T1027.002** — Obfuscated Files or Information: Software Packing
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Endpoint contact with attacker C2 setup-service.com (OpenClaw skill stager)

`UC_520_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*setup-service.com*" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="setup-service.com" OR All_Traffic.dest_host="setup-service.com" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | append [| tstats summariesonly=t count from datamodel=Web.Web where Web.url="*setup-service.com*" by Web.src Web.url Web.http_user_agent | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "setup-service.com" or RemoteUrl endswith ".setup-service.com"
 | project Timestamp, DeviceName, User=InitiatingProcessAccountName, Tool=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Source="DeviceNetwork"),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType in ("DnsQueryResponse","ConnectionSuccess","ConnectionFailed")
 | where RemoteUrl has "setup-service.com" or AdditionalFields has "setup-service.com"
 | project Timestamp, DeviceName, User=InitiatingProcessAccountName, Tool=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteUrl, RemoteIP, Source="DeviceEvents")
| order by Timestamp desc
```

### [LLM] Pastebin-piping stager retrieved from rentry.co/openclaw-core (macOS/Linux ClawHub skill)

`UC_520_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*rentry.co/openclaw-core*" OR Web.url="*rentry.co/raw/openclaw-core*") by Web.src Web.user Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | append [| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.process="*rentry.co/openclaw-core*" OR Processes.process="*rentry.co/raw/openclaw-core*") (Processes.process_name IN ("curl","wget","bash","sh","zsh","osascript","pwsh","powershell.exe","curl.exe","wget.exe") OR Processes.parent_process_name IN ("Terminal","iTerm2","bash","zsh")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "rentry.co/openclaw-core" or RemoteUrl has "rentry.co/raw/openclaw-core"
 | project Timestamp, DeviceName, User=InitiatingProcessAccountName, Tool=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteUrl, Source="NetworkEvents"),
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where ProcessCommandLine has_any ("rentry.co/openclaw-core","rentry.co/raw/openclaw-core")
     or InitiatingProcessCommandLine has_any ("rentry.co/openclaw-core","rentry.co/raw/openclaw-core")
 | where FileName in~ ("curl","curl.exe","wget","wget.exe","bash","sh","zsh","pwsh","powershell.exe","osascript")
     or InitiatingProcessFileName in~ ("curl","curl.exe","wget","wget.exe","bash","sh","zsh","pwsh","powershell.exe","osascript","Terminal","iTerm2")
 | project Timestamp, DeviceName, User=AccountName, FileName, ProcessCommandLine, ParentImage=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine, Source="ProcessEvents")
| order by Timestamp desc
```

### [LLM] Download of openclawcore-1.0.3.zip from denboss99 GitHub release (Windows OpenClaw skill payload)

`UC_520_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*github.com/denboss99/openclaw-core*" OR Web.url="*openclawcore-1.0.3.zip*" OR Web.url="*aztr0nutz/NET_NINJA*") by Web.src Web.user Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | append [| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="openclawcore-1.0.3.zip" OR Filesystem.file_name="openclaw-core*" OR Filesystem.file_path="*openclawcore*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has_any ("github.com/denboss99/openclaw-core","openclawcore-1.0.3.zip","aztr0nutz/NET_NINJA")
 | project Timestamp, DeviceName, User=InitiatingProcessAccountName, Tool=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteUrl, Source="NetworkEvents"),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FileName =~ "openclawcore-1.0.3.zip"
     or FileName matches regex @"(?i)^openclawcore[-_].*\.zip$"
     or FolderPath has "openclawcore"
     or FileOriginUrl has_any ("github.com/denboss99/openclaw-core","openclawcore-1.0.3.zip")
 | project Timestamp, DeviceName, User=InitiatingProcessAccountName, ActionType, FileName, FolderPath, FileOriginUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, Source="FileEvents")
| order by Timestamp desc
```

### [LLM] SKILL.md file written referencing fabricated openclaw-core prerequisite (ClawHub skill social engineering hook)

`UC_520_7` · phase: **weapon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="SKILL.md" OR Filesystem.file_name="skill.md") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | join type=inner dest [search index=* sourcetype IN ("clawhub:*","openclaw:*","defender:files") ("openclaw-core" OR "rentry.co/openclaw-core" OR "denboss99/openclaw-core" OR "aztr0nutz/NET_NINJA" OR "google-qx4" OR "NET_NiNjA") | stats values(_raw) as raw by host | rename host as dest]
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "SKILL.md"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, User=InitiatingProcessAccountName, FolderPath, FileName, SHA256, FileOriginUrl, Tool=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("openclaw-core","rentry.co/openclaw-core","denboss99/openclaw-core","aztr0nutz/NET_NINJA","google-qx4","NET_NiNjA")
    | project DeviceName, User=AccountName, ContextCmd=ProcessCommandLine, ContextTime=Timestamp
) on DeviceName, User
| where abs(datetime_diff('second', Timestamp, ContextTime)) <= 600
| project Timestamp, DeviceName, User, FolderPath, FileName, Tool, Cmd, ContextCmd, SHA256
| order by Timestamp desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `setup-service.com`, `rentry.co/openclaw-core`, `github.com/denboss99/openclaw-core`, `github.com/aztr0nutz/NET_NINJA.v1.2`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
