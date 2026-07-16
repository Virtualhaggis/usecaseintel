# [HIGH] Harden-Runner Block Mode Now Available for macOS and Windows GitHub-Hosted Runners

**Source:** StepSecurity
**Published:** 2026-07-16
**Article:** https://www.stepsecurity.io/blog/harden-runner-block-mode-now-available-for-macos-and-windows-github-hosted-runners

## Threat Profile

Back to Blog Product Harden-Runner Block Mode Now Available for macOS and Windows GitHub-Hosted Runners Harden-Runner v2.20.0 extends egress block mode to macOS and Windows GitHub-hosted runners, so you can stop secret exfiltration on every OS your pipelines run on, not just observe it. Ashish Kurmi View LinkedIn July 15, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Harden-Runner v2.20.0 extends egress block mode to macOS a…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.36.224.5`
- **IPv4 (defanged):** `216.126.225.129`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1567.002** — Exfiltration to Cloud Storage
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1543.004** — Create or Modify System Process: Launch Daemon

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised @velora-dex/sdk npm package (9.4.1/9.4.2) installed on CI runner

`UC_4_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*@velora-dex*sdk*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "@velora-dex/sdk" or FolderPath has @"@velora-dex\sdk"
| where FileName endswith ".js" or FileName =~ "package.json"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### CI runner egress to MiniRAT C2 89.36.224.5 (Velora SDK backdoor)

`UC_4_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="89.36.224.5" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "89.36.224.5"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### CI runner egress to Megalodon secret-exfil C2 216.126.225.129:8443

`UC_4_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="216.126.225.129" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "216.126.225.129"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### MiniRAT launchctl persistence established during macOS CI build

`UC_4_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="launchctl" (Processes.process="*load*" OR Processes.process="*bootstrap*" OR Processes.process="*submit*") (Processes.parent_process_name="bash" OR Processes.parent_process_name="sh" OR Processes.parent_process_name="zsh" OR Processes.parent_process_name="node" OR Processes.parent_process_name="curl") by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "launchctl"
| where ProcessCommandLine has_any ("load","bootstrap","submit")
| where InitiatingProcessFileName in~ ("bash","sh","zsh","node","curl")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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
  - IP / domain IOC(s): `89.36.224.5`, `216.126.225.129`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
