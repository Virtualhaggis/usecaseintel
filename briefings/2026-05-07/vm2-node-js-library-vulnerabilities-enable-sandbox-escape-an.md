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
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1211** — Exploitation for Defense Evasion

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] node.exe spawning OS shell or LOLBin child — vm2 sandbox-escape RCE via child_process

`UC_3_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","sh","bash","dash","zsh") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where NOT match(user, "(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// vm2 sandbox-escape RCE — node.exe spawning OS shell / LOLBin
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","sh","bash","dash","zsh")
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
// Suppress legitimate npm/build tool chains — tune to your CI hosts
| where InitiatingProcessCommandLine !has "npm-cli.js"
    and InitiatingProcessCommandLine !has "yarn.js"
    and InitiatingProcessCommandLine !has "\\node-gyp"
| project Timestamp, DeviceName, AccountName,
          NodePath = InitiatingProcessFolderPath,
          NodeCmd = InitiatingProcessCommandLine,
          NodeParent = InitiatingProcessParentFileName,
          ChildBin = FileName,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256,
          IsRemoteSession = InitiatingProcessTokenElevation
| order by Timestamp desc
```

### [LLM] vm2 sandbox-escape primitive strings in web traffic or node -e payloads

`UC_3_4` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*__lookupGetter__*" OR Web.url="*SuppressedError*" OR Web.url="*neutralizeArraySpeciesBatch*" OR Web.url="*BaseHandler.getPrototypeOf*" OR Web.url="*getPrototypeOf*" OR Web.url="*Symbol.species*" OR Web.http_user_agent="*vm2*") by Web.src Web.dest Web.site Web.url Web.http_method Web.user_agent Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | appendpipe [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="node.exe" AND (Processes.process="*-e *" OR Processes.process="*--eval*" OR Processes.process="*-p *" OR Processes.process="*--print*") AND (Processes.process="*__lookupGetter__*" OR Processes.process="*SuppressedError*" OR Processes.process="*neutralizeArraySpeciesBatch*" OR Processes.process="*BaseHandler.getPrototypeOf*" OR Processes.process="*child_process*") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` ]
```

**Defender KQL:**
```kql
// vm2 sandbox-escape primitive strings in node -e/--eval (host-visible exploit reproduction or in-process testing)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "node.exe" or InitiatingProcessFileName =~ "node.exe"
| where ProcessCommandLine has_any ("-e ", "--eval", "-p ", "--print")
| where ProcessCommandLine has_any (
    "__lookupGetter__",
    "SuppressedError",
    "neutralizeArraySpeciesBatch",
    "BaseHandler.getPrototypeOf",
    "Symbol.species",
    "constructor.constructor",
    "require('child_process')",
    "require(\"child_process\")",
    "process.mainModule"
  )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentBin = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          FolderPath, SHA256
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

`UC_3_2` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
