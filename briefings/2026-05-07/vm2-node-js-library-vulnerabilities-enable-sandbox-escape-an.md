# [HIGH] vm2 Node.js Library Vulnerabilities Enable Sandbox Escape and Arbitrary Code Execution

**Source:** The Hacker News
**Published:** 2026-05-07
**Article:** https://thehackernews.com/2026/05/vm2-nodejs-library-vulnerabilities.html

## Threat Profile

vm2 Node.js Library Vulnerabilities Enable Sandbox Escape and Arbitrary Code Execution 
 Ravie Lakshmanan  May 07, 2026 Vulnerability / Software Security 
A dozen critical security vulnerabilities have been disclosed in the vm2 Node.js library that could be exploited by bad actors to break out of the sandbox and execute arbitrary code on susceptible systems.
vm2 is an open-source library used to run untrusted JavaScript code inside a secure sandbox by intercepting and proxying JavaScript objec…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-24118`
- **CVE:** `CVE-2026-24120`
- **CVE:** `CVE-2023-37466`
- **CVE:** `CVE-2026-24781`
- **CVE:** `CVE-2026-26332`
- **CVE:** `CVE-2026-26956`
- **CVE:** `CVE-2026-43997`
- **CVE:** `CVE-2026-43999`
- **CVE:** `CVE-2026-44005`
- **CVE:** `CVE-2026-44006`
- **CVE:** `CVE-2026-44007`
- **CVE:** `CVE-2026-44008`
- **CVE:** `CVE-2026-44009`
- **CVE:** `CVE-2026-22709`
- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1203** — Exploitation for Client Execution
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] vm2 Node.js Library Vulnerable Versions Exposed (CVE-2026-24118 et al.)

`UC_42_3` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-24118","CVE-2026-24120","CVE-2026-24781","CVE-2026-26332","CVE-2026-26956","CVE-2026-43997","CVE-2026-43999","CVE-2026-44005","CVE-2026-44006","CVE-2026-44007","CVE-2026-44008","CVE-2026-44009","CVE-2026-22709") by Vulnerabilities.dest, Vulnerabilities.cve, Vulnerabilities.signature, Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let vm2_cves = dynamic(["CVE-2026-24118","CVE-2026-24120","CVE-2026-24781","CVE-2026-26332","CVE-2026-26956","CVE-2026-43997","CVE-2026-43999","CVE-2026-44005","CVE-2026-44006","CVE-2026-44007","CVE-2026-44008","CVE-2026-44009","CVE-2026-22709"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId in (vm2_cves)
| where SoftwareName has "vm2" or SoftwareVendor has "vm2" or SoftwareName has "node"
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by VulnerabilitySeverityLevel asc, DeviceName asc
```

### [LLM] Node.js spawning OS shell — vm2 sandbox-escape RCE post-exploitation

`UC_42_4` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdlines values(Processes.process_name) as childBins from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","node") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wmic.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","mshta.exe","regsvr32.exe","rundll32.exe","sh","bash","dash","zsh","ksh") by Processes.dest, Processes.user, Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
// vm2 sandbox escape post-exploit: node spawning OS shell or LOLBin
let shell_or_lolbin = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wmic.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","mshta.exe","regsvr32.exe","rundll32.exe","sh","bash","dash","zsh","ksh"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ (shell_or_lolbin)
// suppress benign npm/build pipelines
| where InitiatingProcessCommandLine !has "npm"
    and InitiatingProcessCommandLine !has "yarn"
    and InitiatingProcessCommandLine !has "\\node-gyp\\"
    and InitiatingProcessParentFileName !in~ ("npm.cmd","yarn.cmd","pnpm.cmd","node.exe")
| project Timestamp, DeviceName, AccountName,
          ParentNode = InitiatingProcessFolderPath,
          ParentNodeCmd = InitiatingProcessCommandLine,
          NodeSHA256 = InitiatingProcessSHA256,
          ChildBin = FileName,
          ChildCmd = ProcessCommandLine,
          IntegrityLevel = ProcessIntegrityLevel,
          IsRemoteSession = InitiatingProcessTokenElevation
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

### Article-specific behavioural hunt — vm2 Node.js Library Vulnerabilities Enable Sandbox Escape and Arbitrary Code Exe

`UC_42_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — vm2 Node.js Library Vulnerabilities Enable Sandbox Escape and Arbitrary Code Exe ```
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
// Article-specific bespoke detection — vm2 Node.js Library Vulnerabilities Enable Sandbox Escape and Arbitrary Code Exe
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
  - CVE(s): `CVE-2026-24118`, `CVE-2026-24120`, `CVE-2023-37466`, `CVE-2026-24781`, `CVE-2026-26332`, `CVE-2026-26956`, `CVE-2026-43997`, `CVE-2026-43999` _(+9 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
