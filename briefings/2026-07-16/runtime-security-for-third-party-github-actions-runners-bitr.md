# [HIGH] Runtime Security for Third-Party GitHub Actions Runners: Bitrise, Blacksmith, Depot, Namespace, and Warp

**Source:** StepSecurity
**Published:** 2026-07-16
**Article:** https://www.stepsecurity.io/blog/runtime-security-for-third-party-github-actions-runners

## Threat Profile

Back to Blog Product Runtime Security for Third-Party GitHub Actions Runners: Bitrise, Blacksmith, Depot, Namespace, and Warp Harden-Runner secures third-party GitHub Actions runners. Bitrise macOS runners join Blacksmith, Depot, Namespace, and Warp Build with v2.20.0 Eromosele Akhigbe View LinkedIn July 16, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Supply chain attacks do not check your runs-on label. When the Sha1-Hulu…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.36.224.5`
- **IPv4 (defanged):** `208.115.220.17`
- **Domain (defanged):** `datahub.ink`
- **Domain (defanged):** `cloud-sync.online`
- **Domain (defanged):** `byte-io.us`
- **SHA256:** `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`
- **SHA256:** `0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.003** — Malicious Package
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious @velora-dex/sdk (9.4.1/9.4.2) pulled into GitHub Actions build runner

`UC_158_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*velora-dex/sdk*" NOT Processes.process="*9.4.0*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "velora-dex/sdk" or InitiatingProcessCommandLine has "velora-dex/sdk"
| where not(ProcessCommandLine has "velora-dex/sdk@9.4.0" or InitiatingProcessCommandLine has "velora-dex/sdk@9.4.0")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Build runner beacon/exfil to Velora backdoor C2 (89.36.224.5 / datahub.ink)

`UC_158_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("89.36.224.5","datahub.ink","cloud-sync.online","byte-io.us")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "89.36.224.5"
   or RemoteUrl has_any ("datahub.ink","cloud-sync.online","byte-io.us")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Velora macOS backdoor launchctl persistence (com.apple.Terminal.profiler.plist)

`UC_158_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="com.apple.Terminal.profiler.plist" OR Filesystem.file_path="*com.apple.Terminal/profiler*" OR Filesystem.file_hash IN ("0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270","0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has "/Library/LaunchAgents/" and FileName =~ "com.apple.Terminal.profiler.plist")
   or FolderPath has "com.apple.Terminal/profiler"
   or SHA256 in ("0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270","0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### npm/node install-time payload: package manager spawning curl/launchctl/osascript on a runner

`UC_158_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","npm","yarn","pnpm","bun") AND Processes.process_name IN ("curl","wget","osascript","launchctl","chmod")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node","npm","yarn","pnpm","bun")
| where FileName in~ ("curl","wget","osascript","launchctl","chmod")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Shai-Hulud worm artifacts written on GitHub Actions runner (shai-hulud-workflow.yml / bundle.js)

`UC_158_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="shai-hulud-workflow.yml" OR Filesystem.file_hash="46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "shai-hulud-workflow.yml"
   or SHA256 == "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
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
  - IP / domain IOC(s): `89.36.224.5`, `208.115.220.17`, `datahub.ink`, `cloud-sync.online`, `byte-io.us`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270`, `0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
