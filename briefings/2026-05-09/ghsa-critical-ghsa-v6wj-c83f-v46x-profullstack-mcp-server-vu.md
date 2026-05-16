# [CRIT] [GHSA / CRITICAL] GHSA-v6wj-c83f-v46x: @profullstack/mcp-server vulnerable to OS Command Injection in domain_lookup Module

**Source:** GitHub Security Advisories
**Published:** 2026-05-09
**Article:** https://github.com/advisories/GHSA-v6wj-c83f-v46x

## Threat Profile

@profullstack/mcp-server vulnerable to OS Command Injection in domain_lookup Module

<html>
<body>
<!--StartFragment--><html><head></head><body><h1>Security Advisory: OS Command Injection in <code>profullstack/mcp-server</code> <code>domain_lookup</code> Module</h1>

Field | Value
-- | --
Project | profullstack/mcp-server
Repository | https://github.com/profullstack/mcp-server
Affected Commit | 2e8ea913573610667ad54e31dba2e8198ebf7cf9
Affected Module | mcp_modules/domain_lookup
Affected Endpoint…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `2e8ea913573610667ad54e31dba2e8198ebf7cf9`

## MITRE ATT&CK Techniques

- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1203** — Exploitation for Client Execution
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] @profullstack/mcp-server tldx OS command injection — shell metachars in tldx process tree

`UC_120_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","npm","pnpm","yarn") OR Processes.parent_process="*mcp-server*" OR Processes.parent_process="*domain_lookup*") (Processes.process_name IN ("sh","bash","dash","tldx") OR Processes.process="*tldx *") Processes.process="*tldx*" (Processes.process="*tldx*;*" OR Processes.process="*tldx*|*" OR Processes.process="*tldx*$(*" OR Processes.process="*tldx*`*" OR Processes.process="*tldx*&&*" OR Processes.process="*tldx*>*" OR Processes.process="*tldx*<(*") by host Processes.user Processes.process_name Processes.parent_process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// GHSA-v6wj-c83f-v46x — tldx command injection via @profullstack/mcp-server
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","npm","pnpm","yarn","npx")
    or InitiatingProcessCommandLine has_any ("mcp-server","domain_lookup","@profullstack/mcp-server")
| where FileName in~ ("sh","bash","dash","tldx") or ProcessCommandLine has "tldx"
| where ProcessCommandLine has "tldx"
// shell metachars that RFC-1035 hostnames/keywords can never contain
| where ProcessCommandLine matches regex @"(?i)tldx[^\r\n]*[;|`&><]|tldx[^\r\n]*\$\("
| project Timestamp, DeviceName, AccountName,
          ParentProc = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildProc  = FileName,
          ChildCmd   = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Unauthenticated POST to @profullstack/mcp-server domain-lookup endpoints from non-loopback source

`UC_120_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.status) as statuses values(Web.url) as urls values(Web.http_user_agent) as agents from datamodel=Web.Web where Web.http_method=POST (Web.url="*/domain-lookup/check*" OR Web.url="*/domain-lookup/bulk*" OR Web.uri_path="*/domain-lookup/check*" OR Web.uri_path="*/domain-lookup/bulk*") by Web.src Web.dest Web.http_method Web.uri_path | `drop_dm_object_name(Web)` | where NOT (cidrmatch("127.0.0.0/8",src) OR cidrmatch("::1/128",src) OR cidrmatch("10.0.0.0/8",src) OR cidrmatch("172.16.0.0/12",src) OR cidrmatch("192.168.0.0/16",src)) | convert ctime(firstTime) ctime(lastTime) | sort - count
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-v6wj-c83f-v46x: @profullstack/mcp-server vulnerable to OS

`UC_120_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-v6wj-c83f-v46x: @profullstack/mcp-server vulnerable to OS ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/verify-exports/final_check.txt*" OR Filesystem.file_path="*/tmp/verify-exports/final_bulk.txt*" OR Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-v6wj-c83f-v46x: @profullstack/mcp-server vulnerable to OS
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/verify-exports/final_check.txt", "/tmp/verify-exports/final_bulk.txt") or FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2e8ea913573610667ad54e31dba2e8198ebf7cf9`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
