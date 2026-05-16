# [HIGH] Critical Remote Code Execution Vulnerabilities Discovered in React Server Components and Next.js

**Source:** StepSecurity
**Published:** 2025-12-15
**Article:** https://www.stepsecurity.io/blog/critical-remote-code-execution-vulnerabilities-discovered-in-react-server-components-and-next-js

## Threat Profile

Back to Blog Resources Critical Remote Code Execution Vulnerabilities Discovered in React Server Components and Next.js Security researchers have uncovered severe unauthenticated remote code execution vulnerabilities in React Server Components and Next.js App Router that achieve near 100% exploitation success rates. With 39% of cloud environments running vulnerable versions and 44% having publicly exposed Next.js instances, immediate patching is critical. Organizations should upgrade to patched …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2025-66478`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1082** — System Information Discovery
- **T1505.003** — Server Software Component: Web Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Next.js/Node.js Server Spawning Recon or Shell Utilities (React2Shell Post-RCE)

`UC_528_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as child_processes dc(Processes.process_name) as unique_children values(Processes.process) as cmdlines values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name="node" OR Processes.parent_process_name="node.exe" OR Processes.parent_process_name="bun" OR Processes.parent_process_name="bun.exe" OR Processes.parent_process_name="next-server") (Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash" OR Processes.process_name="curl" OR Processes.process_name="wget" OR Processes.process_name="chmod" OR Processes.process_name="id" OR Processes.process_name="whoami" OR Processes.process_name="hostname" OR Processes.process_name="python3" OR Processes.process_name="nohup" OR Processes.process_name="killall" OR Processes.process_name="sed" OR Processes.process="*base64 -d*" OR Processes.process="*/etc/hosts*" OR Processes.process="*/etc/resolv.conf*" OR Processes.process="*/dev/tcp/*" OR Processes.process="*hostname -I*" OR Processes.process="*uname -a*") by Processes.dest Processes.parent_process_name Processes.parent_process_id _time span=5m | `drop_dm_object_name(Processes)` | stats min(firstTime) as firstTime max(lastTime) as lastTime values(child_processes) as child_processes dc(child_processes) as unique_children values(cmdlines) as cmdlines values(user) as user by dest parent_process_name parent_process_id | where unique_children>=2 OR mvfilter(match(cmdlines,"/dev/tcp/|base64 -d|/etc/hosts|filemanager-standalone|segawon\.txt"))!="" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// React2Shell (CVE-2025-55182 / CVE-2025-66478) post-exploitation
// Hunts Node.js / Bun runtimes spawning recon + download utilities
let _recon_children = dynamic(["sh","bash","dash","curl","wget","chmod","id","whoami","hostname","python3","nohup","killall","sed","uname","cat"]);
let _recon_strings = dynamic(["/etc/hosts","/etc/resolv.conf","/dev/tcp/","base64 -d","uname -a","hostname -I","filemanager-standalone","segawon.txt"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe","next-server")
| where FileName in~ (_recon_children) or ProcessCommandLine has_any (_recon_strings)
| summarize EarliestTime=min(Timestamp), LatestTime=max(Timestamp),
            ChildProcesses=make_set(FileName, 50),
            UniqueChildren=dcount(FileName),
            ChildCmdLines=make_set(ProcessCommandLine, 50),
            ReconHit=countif(ProcessCommandLine has_any (_recon_strings))
          by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| where UniqueChildren >= 2 or ReconHit > 0
| order by LatestTime desc
```

### [LLM] React2Shell C2 Infrastructure Egress from Node.js / Web Tier

`UC_528_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="156.234.209.103" OR All_Traffic.dest="45.32.158.54" OR All_Traffic.dest="46.36.37.85" OR All_Traffic.dest="115.42.60.223" OR All_Traffic.dest="193.24.123.68" OR All_Traffic.dest="140.99.223.178") by All_Traffic.dest All_Traffic.src All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// React2Shell (CVE-2025-55182) C2 / payload-hosting IPs — Unit 42 IOC set
let _react2shell_ips = dynamic(["156.234.209.103","45.32.158.54","46.36.37.85","115.42.60.223","193.24.123.68","140.99.223.178"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (_react2shell_ips)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          InitiatingProcessAccountName, ActionType
| order by Timestamp desc
```

### [LLM] React2Shell Web Shell Artifact Drop (filemanager-standalone.js / segawon.txt)

`UC_528_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name="filemanager-standalone.js" OR Filesystem.file_name="segawon.txt" OR Filesystem.file_name="sex.sh") by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process="*bash -i*" AND Processes.process="*/dev/tcp/*") OR (Processes.process="*filemanager-standalone*") OR (Processes.process="*segawon.txt*") by Processes.dest Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// React2Shell (CVE-2025-55182 / CVE-2025-66478) web-shell + reverse-shell artifacts
let _react2shell_files = dynamic(["filemanager-standalone.js","segawon.txt","sex.sh"]);
let _react2shell_ports = dynamic(["13373","8899"]);
union isfuzzy=true
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (_react2shell_files) or FileName matches regex @"(?i)filemanager-standalone.*\.js$"
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, Source="DeviceFileEvents" ),
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "bash -i" and ProcessCommandLine has "/dev/tcp/"
         or ProcessCommandLine has_any (_react2shell_files)
         or (ProcessCommandLine has "sed" and ProcessCommandLine has "PORT" and ProcessCommandLine has_any (_react2shell_ports))
    | project Timestamp, DeviceName, ActionType="ProcessCreated",
              FileName, FolderPath=InitiatingProcessFolderPath,
              InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine,
              InitiatingProcessAccountName=AccountName, Source="DeviceProcessEvents" )
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

### Article-specific behavioural hunt — Critical Remote Code Execution Vulnerabilities Discovered in React Server Compon

`UC_528_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Critical Remote Code Execution Vulnerabilities Discovered in React Server Compon ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Critical Remote Code Execution Vulnerabilities Discovered in React Server Compon
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`, `CVE-2025-66478`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
