# [HIGH] Roblox executors: It’s all fun and games until someone gets hacked

**Source:** ESET WeLiveSecurity
**Published:** 2025-09-26
**Article:** https://www.welivesecurity.com/en/kids-online/roblox-executors-fun-games-someone-gets-hacked/

## Threat Profile

Every day, tens of millions of young people dive into Roblox to build, connect and compete. But with that scale comes opportunity, not just for game designers and players, but also for cybercriminals who disguise malware as cheat tools promising quick wins. There are countless threads on Discord , Reddit , YouTube , and other websites that promote various cheats as harmless tools. And because Roblox has such a grip on kids and teens, the temptation that freebies hold is often too strong to ignor…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1204.002** — User Execution: Malicious File
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1566.002** — Phishing: Spearphishing Link
- **T1082** — System Information Discovery
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Chaos ransomware masquerading as Solara Roblox executor binary

`UC_349_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("SolaraBootstrapper.exe","Solara-Roblox-Executor-v3.exe","solara-1.0.1.exe","RobloxInjector.exe") OR Processes.process_hash="6120fb34ef61c7379348b5a1fb6baea5508a8846e70b27460f2c640675dc570b" OR Processes.process_path IN ("*\\Temp\\solara*","*\\Downloads\\Solara*","*\\Downloads\\RobloxInjector*","*\\Downloads\\Synapse*","*\\Downloads\\Krnl*","*\\Downloads\\Fluxus*")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where FileName in~ ("SolaraBootstrapper.exe","Solara-Roblox-Executor-v3.exe","solara-1.0.1.exe","RobloxInjector.exe")
    or SHA256 == "6120fb34ef61c7379348b5a1fb6baea5508a8846e70b27460f2c640675dc570b"
    or FolderPath has_any (@"\Temp\solara", @"\Downloads\Solara", @"\Downloads\RobloxInjector", @"\Downloads\Synapse", @"\Downloads\Krnl", @"\Downloads\Fluxus")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### [LLM] Download of fake Solara executor from known malicious GitHub release paths

`UC_349_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url IN ("*github.com/bow16nelson/Solara-Executor-Roblox/releases/download/*","*fuzzy-octo-couscous/releases/download/*","*solara-executor-1-pc-roblox-executor.github.io*") OR Web.url="*RobloxInjector.zip" OR Web.url="*intera.rar" OR Web.url="*Solara-Roblox-Executor-v3.exe" OR Web.url="*SolaraBootstrapper.exe") by Web.src Web.user Web.url Web.dest Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("github.com/bow16nelson/Solara-Executor-Roblox/releases/download", "fuzzy-octo-couscous/releases/download", "solara-executor-1-pc-roblox-executor.github.io")
    or RemoteUrl endswith "RobloxInjector.zip"
    or RemoteUrl endswith "intera.rar"
    or RemoteUrl endswith "Solara-Roblox-Executor-v3.exe"
    or RemoteUrl endswith "SolaraBootstrapper.exe"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

### [LLM] Roblox executor masquerade performs WMIC UUID fingerprint and schtasks persistence

`UC_349_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("SolaraBootstrapper.exe","Solara-Roblox-Executor-v3.exe","solara-1.0.1.exe","RobloxInjector.exe","Synapse.exe","Krnl.exe","Fluxus.exe") AND ((Processes.process_name="wmic.exe" AND Processes.process="*csproduct*UUID*") OR (Processes.process_name="schtasks.exe" AND Processes.process="*/create*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | stats values(process_name) as child_procs values(process) as cmds dc(process_name) as child_variety by dest user parent_process_name | where child_variety>=2
```

**Defender KQL:**
```kql
let executors = dynamic(["SolaraBootstrapper.exe","Solara-Roblox-Executor-v3.exe","solara-1.0.1.exe","RobloxInjector.exe","Synapse.exe","Krnl.exe","Fluxus.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (executors)
| where (FileName =~ "wmic.exe" and ProcessCommandLine has "csproduct" and ProcessCommandLine has "UUID")
   or (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create")
| summarize ChildProcs=make_set(FileName), Cmds=make_set(ProcessCommandLine), Variety=dcount(FileName) by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Variety >= 2
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
