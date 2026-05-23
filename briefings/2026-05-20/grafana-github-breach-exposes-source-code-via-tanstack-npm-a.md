# [HIGH] Grafana GitHub Breach Exposes Source Code via TanStack npm Attack

**Source:** The Hacker News
**Published:** 2026-05-20
**Article:** https://thehackernews.com/2026/05/grafana-github-breach-exposes-source.html

## Threat Profile

Grafana GitHub Breach Exposes Source Code via TanStack npm Attack 
 Ravie Lakshmanan  May 20, 2026 Supply Chain Attack / Cloud Security 
Grafana Labs, on May 19, 2026, said an investigation into its recent breach found no evidence of customer production systems or operations being compromised.
It said the scope of the incident is limited to the Grafana Labs GitHub environment, which includes public and private source code along with internal GitHub repositories.
"After the initial assessment, …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `filev2.getsession.org`
- **Domain (defanged):** `api.masscan.cloud`
- **SHA256:** `ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`
- **SHA256:** `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — Malicious File
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1555.005** — Password Managers
- **T1528** — Steal Application Access Token
- **T1021.007** — Remote Services: Cloud Services
- **T1651** — Cloud Administration Command
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1568** — Dynamic Resolution
- **T1485** — Data Destruction
- **T1657** — Financial Theft
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious durabletask PyPI package install (versions 1.4.1-1.4.3)

`UC_79_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip","pip3","python","python3","poetry","uv") AND Processes.process="*durabletask*" AND (Processes.process="*1.4.1*" OR Processes.process="*1.4.2*" OR Processes.process="*1.4.3*")) by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Trojanized durabletask install — TeamPCP Mini Shai-Hulud
let bad_versions = dynamic(["durabletask==1.4.1","durabletask==1.4.2","durabletask==1.4.3","durabletask-1.4.1","durabletask-1.4.2","durabletask-1.4.3"]);
let ProcessHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("pip","pip3","python","python3","poetry","uv")
    | where ProcessCommandLine has "durabletask"
    | where ProcessCommandLine matches regex @"durabletask[\s=<>~!\-_]+1\.4\.[123](\D|$)"
       or ProcessCommandLine has_any (bad_versions)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceType="ProcessExec";
let FileHits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has "site-packages"
    | where FolderPath matches regex @"durabletask[-_]1\.4\.[123]"
       or FileName matches regex @"durabletask[-_]1\.4\.[123]"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceType="FileWrite";
union ProcessHits, FileHits
| order by Timestamp desc
```

### [LLM] Python interpreter fetches rope.pyz dropper from check.git-service.com

`UC_79_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where ((All_Traffic.dest IN ("check.git-service.com","t.m-kosche.com") OR All_Traffic.dest_ip="83.142.209.194") AND All_Traffic.app IN ("python","python3","curl","wget","pip","pip3")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// rope.pyz second-stage retrieval — TeamPCP C2 domains
let c2_domains = dynamic(["check.git-service.com","t.m-kosche.com"]);
let c2_ips = dynamic(["83.142.209.194"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has_any (c2_domains)) or (RemoteIP in (c2_ips))
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, EvidenceType="NetworkConnect";
let RopeFile = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "rope.pyz"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName="", RemoteUrl=FileOriginUrl, RemoteIP=tostring(FileOriginIP), RemotePort=int(null), EvidenceType="FileDrop";
union NetHits, RopeFile
| order by Timestamp desc
```

### [LLM] Linux Python stealer harvesting cloud, vault, SSH and password-manager secrets

`UC_79_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Filesystem.file_path) as paths_touched dc(Filesystem.file_path) as path_count from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("python","python3") (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.bash_history" OR Filesystem.file_path="*/.zsh_history" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/1Password*" OR Filesystem.file_path="*/Bitwarden*" OR Filesystem.file_path="*/op/config") by Filesystem.dest Filesystem.user Filesystem.process_guid _time span=5m | `drop_dm_object_name(Filesystem)` | where path_count>=3
```

**Defender KQL:**
```kql
// rope.pyz infostealer cred-harvest fan-out — Linux
let cred_globs = dynamic([
    "/.aws/credentials","/.aws/config",
    "/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/known_hosts",
    "/.docker/config.json","/.dockercfg",
    "/.bash_history","/.zsh_history",
    "/.vault-token",
    "/.config/op","/.config/1Password","/.config/Bitwarden",
    "/.netrc","/.kube/config"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName in ((DeviceInfo | where OSPlatform in ("Linux","linux") | distinct DeviceName))
   or InitiatingProcessFolderPath startswith "/"
| where InitiatingProcessFileName in~ ("python","python3")
| where ActionType in ("FileAccessed","FileCreated","FileModified","FileRenamed")
| extend FullPath = strcat(FolderPath, "/", FileName)
| where FullPath has_any (cred_globs)
| summarize PathsTouched = make_set(FullPath, 50), DistinctPaths = dcount(FullPath), Count = count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
          by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where DistinctPaths >= 3
| order by LastSeen desc
```

### [LLM] Mini Shai-Hulud worm propagation via AWS SSM SendCommand fan-out

`UC_79_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`cloudtrail` eventName=SendCommand eventSource=ssm.amazonaws.com requestParameters.documentName=AWS-RunShellScript (requestParameters.parameters.commands{}="*rope.pyz*" OR requestParameters.parameters.commands{}="*check.git-service.com*" OR requestParameters.parameters.commands{}="*t.m-kosche.com*" OR requestParameters.parameters.commands{}="*curl*") | stats min(_time) as firstTime max(_time) as lastTime dc(requestParameters.instanceIds{}) as instance_count values(requestParameters.instanceIds{}) as instances values(sourceIPAddress) as srcIPs by userIdentity.arn userIdentity.userName userIdentity.accessKeyId | where instance_count>=3 | convert ctime(firstTime) ctime(lastTime)
```

### [LLM] FIRESCALE backup-C2 lookup via GitHub commit-message search

`UC_79_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Web.Web where (Web.url="*api.github.com/search/commits*FIRESCALE*" OR Web.url="*api.github.com*q=FIRESCALE*" OR Web.url="*api.github.com*FIRESCALE*") by Web.src Web.user Web.url Web.app _time | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
// FIRESCALE dead-drop resolver — GitHub commit-search query
let PrimaryUrlHit = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "api.github.com"
    | where RemoteUrl has "FIRESCALE" or RemoteUrl has "search/commits"
    | where RemoteUrl has "FIRESCALE"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, EvidenceType="NetEvent";
let CmdHit = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "api.github.com"
    | where ProcessCommandLine has "FIRESCALE" or (ProcessCommandLine has "search/commits" and ProcessCommandLine has_any ("q=","FIRESCALE"))
    | project Timestamp, DeviceName, InitiatingProcessFileName=FileName, InitiatingProcessCommandLine=ProcessCommandLine, RemoteUrl="", RemoteIP="", EvidenceType="Process";
union PrimaryUrlHit, CmdHit
| order by Timestamp desc
```

### [LLM] Locale-gated destructive payload: python parent spawns rm -rf / on Linux

`UC_79_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3") AND (Processes.process_name IN ("rm","sh","bash","dash")) AND (Processes.process="*rm * -rf */*" OR Processes.process="*rm -rf /" OR Processes.process="*rm -rf /*" OR Processes.process="*--no-preserve-root*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Locale-gated destructive payload — python -> rm -rf /
let RmHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python","python3")
    | where FileName in~ ("rm","sh","bash","dash","zsh")
    | where ProcessCommandLine matches regex @"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)(\s+--no-preserve-root)?\s+(/(\s|$|\*)|/\*)"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, EvidenceType="rm_rf";
let AudioHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python","python3")
    | where FileName in~ ("aplay","paplay","mpg123","ffplay","play")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, EvidenceType="audio_taunt";
let LocaleHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python","python3")
    | where ProcessCommandLine has_any ("he_IL","fa_IR","LANG=he","LANG=fa","locale -a","localectl")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, EvidenceType="locale_check";
union RmHits, AudioHits, LocaleHits
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
  - IP / domain IOC(s): `83.142.209.194`, `git-tanstack.com`, `filev2.getsession.org`, `api.masscan.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ce7e4199506959fd7a71b64209b2c07b9c82e53a946aa7d78298dc9249230d01`, `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`, `2258284d65f63829bd67eaba01ef6f1ada2f593f9bbe41678b2df360bd90d3df`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
