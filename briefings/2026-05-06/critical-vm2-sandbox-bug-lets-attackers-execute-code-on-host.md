# [HIGH] Critical vm2 sandbox bug lets attackers execute code on hosts

**Source:** BleepingComputer
**Published:** 2026-05-06
**Article:** https://www.bleepingcomputer.com/news/security/critical-vm2-sandbox-bug-lets-attackers-execute-code-on-hosts/

## Threat Profile

Critical vm2 sandbox bug lets attackers execute code on hosts 
By Bill Toulas 
May 6, 2026
02:38 PM
0 
A critical vulnerability in the popular Node.js sandboxing library vm2 allows escaping the sandbox and executing arbitrary code on the host system.
The security issue is tracked as CVE-2026-26956 and has been confirmed to impact vm2 version 3.10.4, although earlier releases may also be vulnerable. Proof-of-concept (PoC) exploit code has been published.
In the security advisory, the maintainer s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-26956`
- **CVE:** `CVE-2026-22709`
- **CVE:** `CVE-2023-30547`
- **CVE:** `CVE-2023-29017`
- **CVE:** `CVE-2022-36067`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1059** — Command and Scripting Interpreter
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Node.js process spawning shell or LOLBin children (vm2 CVE-2026-26956 sandbox escape post-exploit)

`UC_26_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","node") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","mshta.exe","regsvr32.exe","rundll32.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","curl","wget","python.exe","python","python3","perl","ruby","whoami.exe","whoami","net.exe","hostname.exe","id","uname") by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// vm2 CVE-2026-26956 — Node.js spawning shells or LOLBins indicates sandbox escape
let _node_parents = dynamic(["node.exe","node"]);
let _suspicious_children = dynamic(["cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","mshta.exe","regsvr32.exe","rundll32.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe","curl","wget","python.exe","python","python3","perl","ruby","whoami.exe","whoami","net.exe","hostname.exe","id","uname"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (_node_parents)
| where FileName in~ (_suspicious_children)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256, IsRemote = IsInitiatingProcessRemoteSession
| order by Timestamp desc
```

### [LLM] Inventory hunt: vulnerable vm2 (<3.10.5) installations on Node.js 25 hosts

`UC_26_3` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\vm2\\package.json" OR Filesystem.file_path="*/node_modules/vm2/package.json") by host | `drop_dm_object_name(Filesystem)` | join type=left host [ | tstats summariesonly=true values(Processes.process_version) as node_versions from datamodel=Endpoint.Processes where Processes.process_name IN ("node.exe","node") by host | `drop_dm_object_name(Processes)` ] | search node_versions="25.*" OR node_versions="v25.*" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// vm2 CVE-2026-26956 — surface hosts with vm2 in node_modules + Node 25
let _vm2_hosts = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where (FolderPath has @"\node_modules\vm2\" or FolderPath has "/node_modules/vm2/")
    | where FileName =~ "package.json"
    | summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Paths = make_set(FolderPath, 10) by DeviceId, DeviceName;
let _node25_hosts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("node.exe","node")
    | where ProcessVersionInfoProductVersion startswith "25." or ProcessVersionInfoProductVersion startswith "v25."
        or ProcessCommandLine matches regex @"(?i)node[/\\\.exe]*\s+--version.*25\."
    | summarize NodeVersions = make_set(ProcessVersionInfoProductVersion, 10), NodeCmdSamples = make_set(ProcessCommandLine, 5) by DeviceId, DeviceName;
_vm2_hosts
| join kind=inner _node25_hosts on DeviceId
| project DeviceName, FirstSeen, LastSeen, Paths, NodeVersions, NodeCmdSamples
| order by LastSeen desc
```

### Article-specific behavioural hunt — Critical vm2 sandbox bug lets attackers execute code on hosts

`UC_26_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Critical vm2 sandbox bug lets attackers execute code on hosts ```
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
// Article-specific bespoke detection — Critical vm2 sandbox bug lets attackers execute code on hosts
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
  - CVE(s): `CVE-2026-26956`, `CVE-2026-22709`, `CVE-2023-30547`, `CVE-2023-29017`, `CVE-2022-36067`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
