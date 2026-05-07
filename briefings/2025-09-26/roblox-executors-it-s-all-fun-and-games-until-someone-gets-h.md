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
- **T1204.002** — User Execution: Malicious File
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1588.001** — Obtain Capabilities: Malware
- **T1490** — Inhibit System Recovery
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1555** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Roblox script executor binary execution (Solara, KRNL, Fluxus, Synapse X, Wave) on managed endpoint

`UC_334_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where (Processes.process_name IN ("SolaraBootstrapper.exe","Solara.exe","Solara-Roblox-Executor-v3.exe","KRNL.exe","Krnl.exe","Fluxus.exe","FluxusZ.exe","SynapseX.exe","Synapse.exe","WaveExecutor.exe","Wave.exe","ScriptWare.exe","Electron.exe") OR Processes.process_name="*Solara*" OR Processes.process_name="*Roblox*Executor*" OR Processes.process_name="*Roblox*Cheat*" OR Processes.process_hash IN ("D2B09B1BDA10143724A24534E31D44DB","6120fb34ef61c7379348b5a1fb6baea5508a8846e70b27460f2c640675dc570b")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("SolaraBootstrapper.exe","Solara.exe","Solara-Roblox-Executor-v3.exe","KRNL.exe","Krnl.exe","Fluxus.exe","FluxusZ.exe","SynapseX.exe","Synapse.exe","WaveExecutor.exe","Wave.exe","ScriptWare.exe")
   or FileName has_any ("solara","synapsex","fluxus")
   or ProcessCommandLine has_any ("Solara-Roblox-Executor","SolaraBootstrapper","KRNL.exe","Fluxus.exe")
   or SHA256 =~ "6120fb34ef61c7379348b5a1fb6baea5508a8846e70b27460f2c640675dc570b"
   or MD5    =~ "D2B09B1BDA10143724A24534E31D44DB"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] Chaos ransomware behaviour following fake Solara/Roblox-executor launch (shadow-copy wipe)

`UC_334_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where ((Processes.process_name="vssadmin.exe" AND Processes.process="*delete*shadows*") OR (Processes.process_name="wmic.exe" AND Processes.process="*shadowcopy*" AND Processes.process="*delete*") OR (Processes.process_name="bcdedit.exe" AND Processes.process="*recoveryenabled*no*") OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND Processes.process="*Win32_Shadowcopy*")) AND (Processes.parent_process_name IN ("SolaraBootstrapper.exe","Solara.exe","Solara-Roblox-Executor-v3.exe","KRNL.exe","Fluxus.exe","SynapseX.exe","Wave.exe") OR Processes.parent_process="*Solara*" OR Processes.parent_process="*\\Roblox\\Executor*" OR Processes.parent_process="*\\KRNL\\*" OR Processes.parent_process="*\\Fluxus\\*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or  (FileName =~ "wmic.exe"     and ProcessCommandLine has_all ("shadowcopy","delete"))
   or  (FileName =~ "bcdedit.exe"  and ProcessCommandLine has "recoveryenabled" and ProcessCommandLine has "no")
   or  (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Win32_Shadowcopy","Remove-WmiObject Win32_Shadowcopy"))
| where InitiatingProcessFileName in~ ("SolaraBootstrapper.exe","Solara.exe","Solara-Roblox-Executor-v3.exe","KRNL.exe","Krnl.exe","Fluxus.exe","FluxusZ.exe","SynapseX.exe","WaveExecutor.exe","Wave.exe")
   or InitiatingProcessFileName has_any ("solara","synapsex","fluxus")
   or InitiatingProcessParentFileName has_any ("solara","krnl","fluxus","synapsex","wave")
   or InitiatingProcessFolderPath has_any (@"\Solara\", @"\KRNL\", @"\Fluxus\", @"\Roblox\Executor\", @"\SynapseX\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath, GrandParent = InitiatingProcessParentFileName,
          InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] Roblox executor process beaconing to LummaC2 .shop infrastructure

`UC_334_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name IN ("SolaraBootstrapper.exe","Solara.exe","Solara-Roblox-Executor-v3.exe","KRNL.exe","Krnl.exe","Fluxus.exe","FluxusZ.exe","SynapseX.exe","WaveExecutor.exe","Wave.exe") OR All_Traffic.process_name="*Solara*") AND (All_Traffic.dest IN ("nearycrepso.shop","fancywaxxers.shop","cloudewahsj.shop","noisycuttej.shop","abruptyopsn.shop","wholersorie.shop","rabidcowse.shop","framekgirus.shop","tirepublicerj.shop") OR All_Traffic.url="*nearycrepso.shop*" OR All_Traffic.url="*fancywaxxers.shop*" OR All_Traffic.url="*cloudewahsj.shop*" OR All_Traffic.url="*noisycuttej.shop*" OR All_Traffic.url="*abruptyopsn.shop*" OR All_Traffic.url="*wholersorie.shop*" OR All_Traffic.url="*rabidcowse.shop*" OR All_Traffic.url="*framekgirus.shop*" OR All_Traffic.url="*tirepublicerj.shop*") by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.url | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let LummaShopDomains = dynamic(["nearycrepso.shop","fancywaxxers.shop","cloudewahsj.shop","noisycuttej.shop","abruptyopsn.shop","wholersorie.shop","rabidcowse.shop","framekgirus.shop","tirepublicerj.shop"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("SolaraBootstrapper.exe","Solara.exe","Solara-Roblox-Executor-v3.exe","KRNL.exe","Krnl.exe","Fluxus.exe","FluxusZ.exe","SynapseX.exe","WaveExecutor.exe","Wave.exe")
   or InitiatingProcessFileName has_any ("solara","synapsex","fluxus")
   or InitiatingProcessFolderPath has_any (@"\Solara\", @"\KRNL\", @"\Fluxus\", @"\Roblox\Executor\")
| where RemoteUrl has_any (LummaShopDomains)
   or RemoteUrl endswith ".shop"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessSHA256, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
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
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
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
| where AccountName !endswith "$"
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
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
