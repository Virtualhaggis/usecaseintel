# [CRIT] Analysis of Backdoored XZ Utils Build Process with Harden-Runner

**Source:** StepSecurity
**Published:** 2026-02-11
**Article:** https://www.stepsecurity.io/blog/analysis-of-backdoored-xz-utils-build-process-with-harden-runner

## Threat Profile

Back to Blog Resources Analysis of Backdoored XZ Utils Build Process with Harden-Runner We analyzed the XZ Utils build process using StepSecurity Harden-Runner and observed the injection of the backdoor. This analysis shows the importance of runtime security monitoring during the build process and how it can help detect such supply chain attacks. Varun Sharma View LinkedIn October 14, 2024
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading na…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-3094`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1554** — Compromise Host Software Binary
- **T1140** — Deobfuscate/Decode Files or Information
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1027.004** — Obfuscated Files or Information: Compile After Delivery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] XZ Utils backdoor: liblzma object file written by shell during build (CVE-2024-3094)

`UC_387_3` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name="liblzma_la-crc64-fast.o" AND Filesystem.process_name IN ("dash","sh","bash","ash","zsh") by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// CVE-2024-3094 — liblzma_la-crc64-fast.o written by a POSIX shell instead of the assembler/linker
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "liblzma_la-crc64-fast.o"
| where InitiatingProcessFileName in~ ("dash","sh","bash","ash","zsh")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          InitiatingProcessParentFileName, ReportId
| order by Timestamp desc
```

### [LLM] XZ Utils backdoor: bad-3-corrupt_lzma2.xz test file referenced or decoded during build (CVE-2024-3094)

`UC_387_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process="*bad-3-corrupt_lzma2.xz*" OR Processes.process="*good-large_compressed.lzma*") by Processes.dest Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// CVE-2024-3094 — process command line references the malicious XZ test files used as backdoor stagers
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("bad-3-corrupt_lzma2.xz","good-large_compressed.lzma")
   or InitiatingProcessCommandLine has_any ("bad-3-corrupt_lzma2.xz","good-large_compressed.lzma")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, ReportId
| order by Timestamp desc
```

### [LLM] XZ Utils backdoor: GCC reads C source from stdin via -x c - while linking liblzma backdoor object (CVE-2024-3094)

`UC_387_5` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("gcc","cc","clang","x86_64-linux-gnu-gcc","x86_64-linux-gnu-gcc-12","x86_64-linux-gnu-gcc-13") AND Processes.process="*-x c -*" AND Processes.process="*liblzma_la-crc64-fast.o*" by Processes.dest Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// CVE-2024-3094 — compiler invoked with stdin C source AND backdoor object on the same command line
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("gcc","cc","clang","x86_64-linux-gnu-gcc","x86_64-linux-gnu-gcc-12","x86_64-linux-gnu-gcc-13","ld","ld.bfd")
   or InitiatingProcessFileName in~ ("gcc","cc","clang","x86_64-linux-gnu-gcc","ld.bfd")
| where ProcessCommandLine matches regex @"(?i)-x\s+c\s+-(\s|$)"
| where ProcessCommandLine has "liblzma_la-crc64-fast.o"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, ReportId
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

### Article-specific behavioural hunt — Analysis of Backdoored XZ Utils Build Process with Harden-Runner

`UC_387_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Analysis of Backdoored XZ Utils Build Process with Harden-Runner ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/x86_64-linux-gnu-ld.bfd*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Analysis of Backdoored XZ Utils Build Process with Harden-Runner
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/x86_64-linux-gnu-ld.bfd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-3094`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
