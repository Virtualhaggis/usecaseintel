# [CRIT] macOS.Gaslight | Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox

**Source:** SentinelLabs
**Published:** 2026-06-23
**Article:** https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/

## Threat Profile

Adversary 
macOS.Gaslight | Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox 
Phil Stokes 
/
June 23, 2026 
Executive Summary 
SentinelLABS has analyzed a Rust macOS implant that embeds a 3.5 KB prompt-injection payload of 38 fabricated “system” messages, built to steer an LLM-assisted triage pipeline into aborting or refusing its analysis.
Command-and-control runs over a Telegram Bot API polling loop, with AES-GCM payloads over certificate-pinned TLS.
The implant self-redact…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525`
- **SHA256:** `77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca`
- **SHA256:** `baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239`
- **SHA256:** `b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1555.001** — Credentials from Password Stores: Keychain
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1005** — Data from Local System
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### macOS.Gaslight Telegram Bot API C2 polling from non-browser process

`UC_185_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="api.telegram.org" by DNS.src DNS.dest DNS.query
| `drop_dm_object_name("DNS")`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "api.telegram.org"
| where InitiatingProcessFileName !in~ ("Telegram","Telegram.app","Safari","com.apple.Safari","Google Chrome","Google Chrome Helper","firefox","Brave Browser","com.apple.WebKit.Networking","nsurlsessiond")
| summarize ConnCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctMinutes=dcount(bin(Timestamp,1m)) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, RemoteUrl
| order by LastSeen desc
```

### macOS.Gaslight keychain theft + collected_data.zip staging

`UC_185_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("collected_data.zip","login.keychain-db") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_id Filesystem.action
| `drop_dm_object_name("Filesystem")`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where (FileName =~ "collected_data.zip")
    or (FileName =~ "login.keychain-db" and ActionType in ("FileCreated","FileRenamed"))
| where InitiatingProcessFileName !in~ ("backupd","mds","mds_stores","securityd","TimeMachine","cfprefsd")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### macOS.Gaslight LaunchAgent persistence masquerading as com.apple.system.services.activity

`UC_185_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/Library/LaunchAgents/*" OR Filesystem.file_path="*/Library/LaunchDaemons/*") Filesystem.file_name="com.apple.system.services.activity.plist" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_id
| `drop_dm_object_name("Filesystem")`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has "/Library/LaunchAgents/" or FolderPath has "/Library/LaunchDaemons/"
| where FileName has "com.apple.system.services.activity"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### macOS.Gaslight self-staged standalone CPython 3.10.18 fetch (astral-sh python-build-standalone)

`UC_185_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*python-build-standalone*" OR Processes.process="*cpython-3.10.18*" OR Processes.process="*PY_VERSION=3.10.18*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "python-build-standalone"
    or (ProcessCommandLine has "astral-sh" and ProcessCommandLine has "cpython-3.10.18")
    or (ProcessCommandLine has "PY_VERSION=3.10.18" and ProcessCommandLine has "BUILD_DATE=20250708")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### macOS.Gaslight known-bad file hashes (Mach-O implant, BONZAI sibling, Python/bash stages)

`UC_185_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525","77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca","baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239","b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394","5555494492fc075f441637fb9d894913dde3a2ea") by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
let GaslightHashes = dynamic(["6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525","77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca","baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239","b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"]);
let GaslightSha1 = "5555494492fc075f441637fb9d894913dde3a2ea";
union
( DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in~ (GaslightHashes) or SHA1 =~ GaslightSha1 | extend Evidence="Process" | project Timestamp, DeviceName, Evidence, FileName, FolderPath, SHA256, SHA1, ProcessCommandLine ),
( DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in~ (GaslightHashes) or SHA1 =~ GaslightSha1 | extend Evidence="File", ProcessCommandLine=InitiatingProcessCommandLine | project Timestamp, DeviceName, Evidence, FileName, FolderPath, SHA256, SHA1, ProcessCommandLine )
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525`, `77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca`, `baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239`, `b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
