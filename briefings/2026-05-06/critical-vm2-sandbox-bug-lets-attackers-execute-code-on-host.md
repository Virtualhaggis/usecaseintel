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


In the security advisory, the …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-26956`
- **CVE:** `CVE-2026-22709`
- **CVE:** `CVE-2023-30547`
- **CVE:** `CVE-2023-29017`
- **CVE:** `CVE-2022-36067`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1611** — Escape to Host
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable vm2 sandbox library installed (CVE-2026-26956)

`UC_0_2` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_name="package.json" Filesystem.file_path="*\\node_modules\\vm2\\package.json" OR Filesystem.file_path="*/node_modules/vm2/package.json" by host Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | rex field=file_path "vm2[\\\\/](?<vm2_dir>[^\\\\/]+)[\\\\/]package\\.json" | eval cve="CVE-2026-26956", vulnerable_lt="3.10.5", patched="3.11.2" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
// Approach 1: TVM-driven (preferred, uses Defender's vulnerability KB)
let VulnByCve = DeviceTvmSoftwareVulnerabilities
    | where CveId == "CVE-2026-26956"
    | project DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate;
// Approach 2: filesystem-driven fallback — TVM may not yet index npm-package CVEs
let Vm2OnDisk = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "package.json"
    | where FolderPath has @"\node_modules\vm2\" or FolderPath has "/node_modules/vm2/"
    | summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
                SamplePath = any(FolderPath),
                SampleSHA256 = any(SHA256)
                by DeviceId, DeviceName;
Vm2OnDisk
| join kind=leftouter VulnByCve on DeviceId
| extend cve = "CVE-2026-26956", VulnerableIfBelow = "3.10.5", LatestPatched = "3.11.2"
| project Cve = cve, DeviceId, DeviceName, FirstSeen, LastSeen, SamplePath, SampleSHA256,
          SoftwareVersion, RecommendedSecurityUpdate, VulnerableIfBelow, LatestPatched
| order by LastSeen desc
```

### [LLM] node.exe spawning OS shell — possible vm2 sandbox escape post-exploitation

`UC_0_3` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_name) as child_proc from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","/bin/sh","/bin/bash","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe") by host user Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
let _known_node_runners = dynamic([]); // populate with hostnames of legit node-shell tooling (CI runners, build agents) to suppress
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ (
    "cmd.exe","powershell.exe","pwsh.exe",
    "wscript.exe","cscript.exe","mshta.exe",
    "rundll32.exe","regsvr32.exe",
    "certutil.exe","bitsadmin.exe",
    "curl.exe","wget.exe",
    "sh","bash","dash","zsh")
| where DeviceName !in~ (_known_node_runners)
| where InitiatingProcessAccountName !endswith "$"
| extend SuspectVm2Escape = iif(
    InitiatingProcessCommandLine has_any ("vm2","isolated-vm") or
    InitiatingProcessFolderPath has @"\node_modules\",
    "likely", "possible")
| project Timestamp, DeviceName,
          AccountName, AccountDomain,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256, SuspectVm2Escape
| order by Timestamp desc
```

### Article-specific behavioural hunt — Critical vm2 sandbox bug lets attackers execute code on hosts

`UC_0_1` · phase: **exploit** · confidence: **High**

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
