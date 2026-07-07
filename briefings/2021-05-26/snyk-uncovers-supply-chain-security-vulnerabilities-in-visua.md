# [CRIT] Snyk uncovers supply chain security vulnerabilities in Visual Studio Code extensions

**Source:** Snyk
**Published:** 2021-05-26
**Article:** https://snyk.io/blog/vulnerable-visual-studio-code-extensions-marketplace/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
May 26, 2021
0 mins read We have been witnessing an ever growing amount of supply chain security incidents in the wild. Everything from open source package managers security flaws being exploited to continuous integration systems being compromised to software artifacts being backdoored . And now, those incidents are starting to extend to the place where developers spend most of their time: their integrated development environment, and specifically …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2018-12120`
- **CVE:** `CVE-2019-13567`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js debugger/inspector launched bound to all network interfaces (CVE-2018-12120/-13567)

`UC_1425_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=node.exe (Processes.process="*--inspect*" OR Processes.process="*--debug*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| search (process="*0.0.0.0*" OR process="*--debug *" OR process="*--debug" OR process="*--debug-brk*")
| search NOT (process="*--debug=localhost*" OR process="*--debug=127.0.0.1*" OR process="*--inspect=localhost*" OR process="*--inspect=127.0.0.1*")
| `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "node.exe"
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd has_any ("--inspect","--debug")
| where (Cmd has "0.0.0.0") or (Cmd matches regex @"--debug(-brk)?(=|\s|$)")   // 0.0.0.0 = explicit all-interface bind; bare --debug defaults to 0.0.0.0:5858 (CVE-2018-12120)
| where not (Cmd matches regex @"--(inspect|debug)(-brk)?=(localhost|127\.0\.0\.1)")  // drop explicit loopback binds (safe)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Remote (non-loopback) connection to an exposed Node.js debug/inspect port 5858/9229

`UC_1425_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (5858, 9229) All_Traffic.direction=inbound by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| search src!="127.0.0.1" AND src!="::1" AND src!=dest
| `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (5858, 9229)
| where InitiatingProcessFileName in~ ("node.exe","Code.exe")
| where RemoteIPType != "Loopback" and RemoteIP !startswith "127." and RemoteIP != "::1"
| project Timestamp, DeviceName, RemoteIP, RemoteIPType, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — Snyk uncovers supply chain security vulnerabilities in Visual Studio Code extens

`UC_1425_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk uncovers supply chain security vulnerabilities in Visual Studio Code extens ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk uncovers supply chain security vulnerabilities in Visual Studio Code extens
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2018-12120`, `CVE-2019-13567`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
