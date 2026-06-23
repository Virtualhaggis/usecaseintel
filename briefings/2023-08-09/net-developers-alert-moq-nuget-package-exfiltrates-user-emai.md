# [HIGH] .NET developers alert: Moq NuGET package exfiltrates user emails from git

**Source:** Snyk
**Published:** 2023-08-09
**Article:** https://snyk.io/blog/moq-package-exfiltrates-user-emails/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
August 9, 2023
0 mins read Editor's note: August 10, 2023 This blog post has been updated to reflect new information on this live situation. Stay tuned for further updates. 
TL;DR On August 8, 2023, the .NET community was informed that the testing library called Moq exfiltrates developer's emails from their development machine and sends them off to third-party remote servers.
Snyk has already published a security advisory and will alert developers …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `cdn.devlooped.com`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1552.004** — Unsecured Credentials: Private Keys / Files
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1041** — Exfiltration Over C2 Channel
- **T1567.002** — Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### .NET build (dotnet/MSBuild) spawns git config to harvest user.email

`UC_1521_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("dotnet.exe","MSBuild.exe","msbuild.exe","VBCSCompiler.exe") AND Processes.process_name="git.exe" AND Processes.process="*config*user.email*" by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path _time | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("dotnet.exe","MSBuild.exe","VBCSCompiler.exe")
| where FileName =~ "git.exe"
| where ProcessCommandLine has "config" and ProcessCommandLine has "user.email"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Moq SponsorLink email exfil egress to cdn.devlooped.com / SponsorLink blob

`UC_1521_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest LIKE "%devlooped.com" OR All_Traffic.dest LIKE "%sponsorlink%" OR All_Traffic.dest LIKE "%.blob.core.windows.net") AND All_Traffic.src_process_name IN ("dotnet.exe","MSBuild.exe","VBCSCompiler.exe") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.src_process_name _time | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("dotnet.exe","MSBuild.exe","VBCSCompiler.exe")
| where RemoteUrl has_any ("devlooped.com","sponsorlink") or RemoteUrl endswith ".blob.core.windows.net"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Vulnerable Moq 4.20.0 or Devlooped.SponsorLink NuGet package landed on endpoint

`UC_1521_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\packages\\moq\\4.20.0\\*" OR Filesystem.file_path="*\\.nuget\\packages\\moq\\4.20.0\\*" OR Filesystem.file_path="*\\.nuget\\packages\\devlooped.sponsorlink\\*" OR Filesystem.file_path="*\\packages\\devlooped.sponsorlink*\\*" OR Filesystem.file_name="moq.4.20.0.nupkg" OR Filesystem.file_name="Moq.4.20.0.nupkg") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name _time | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where (FolderPath has @"\.nuget\packages\moq\4.20.0\")
    or (FolderPath has @"\packages\moq.4.20.0\")
    or (FolderPath has @"\.nuget\packages\devlooped.sponsorlink\")
    or (FolderPath has @"\packages\devlooped.sponsorlink")
    or (FileName in~ ("moq.4.20.0.nupkg","Moq.4.20.0.nupkg"))
    or (FileName startswith_cs "Devlooped.SponsorLink" and FileName endswith ".nupkg")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
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
  - IP / domain IOC(s): `cdn.devlooped.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
