# [CRIT] [GHSA / CRITICAL] GHSA-4869-x4pr-q22x: PraisonAI: Unauthenticated RCE via Jobs API + Approval Bypass

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-4869-x4pr-q22x

## Threat Profile

PraisonAI: Unauthenticated RCE via Jobs API + Approval Bypass

# Unauthenticated Remote Code Execution via Jobs API and Approval Bypass in PraisonAI
 
## Summary
 
An unauthenticated attacker can execute arbitrary OS commands on any server running
the PraisonAI Jobs API by submitting a crafted workflow YAML. The attack chains two
weaknesses: the `/api/v1/runs` endpoint requires no credentials, and a top-level
`approve` field in the submitted YAML unconditionally bypasses the
`@require_approval` …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI Jobs-API RCE: agent server (python) spawns shell/network utility via execute_command

`UC_112_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*praisonai*" OR Processes.parent_process_path="*praisonai*") AND (Processes.process_name IN ("curl","curl.exe","wget","sh","bash","dash","zsh","ksh","nc","ncat","socat","perl","ruby","php","python","python3","whoami","id","cmd.exe","powershell.exe","pwsh.exe")) by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has "praisonai" or InitiatingProcessFolderPath has "praisonai"
| where FileName in~ ("curl","curl.exe","wget","sh","bash","dash","zsh","ksh","nc","ncat","socat","perl","ruby","php","python","python3","whoami","id","cmd.exe","powershell.exe","pwsh.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Unauthenticated POST to PraisonAI Jobs API (/api/v1/runs, port 8005)

`UC_112_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method="POST" AND Web.url="*/api/v1/runs*" by Web.src Web.dest Web.dest_port Web.http_method Web.url Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 8005
| where InitiatingProcessCommandLine has "praisonai" or InitiatingProcessFileName in~ ("python","python3","uvicorn","gunicorn")
| where RemoteIPType == "Public"
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, LocalPort, InitiatingProcessFileName
| order by Connections desc
```

### Exposure hunt: vulnerable PraisonAI package installed (praisonai <= 4.6.48 / praisonaiagents < 1.6.59)

`UC_112_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "praisonai"
| extend ParsedVersion = parse_version(SoftwareVersion)
| where (SoftwareName =~ "praisonai" and ParsedVersion <= parse_version("4.6.48"))
    or (SoftwareName =~ "praisonaiagents" and ParsedVersion < parse_version("1.6.59"))
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, OSPlatform, EndOfSupportStatus
| order by DeviceName asc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-4869-x4pr-q22x: PraisonAI: Unauthenticated RCE via Jobs A

`UC_112_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-4869-x4pr-q22x: PraisonAI: Unauthenticated RCE via Jobs A ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("yaml_parser.py","workflows.py","shell_tools.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("yaml_parser.py","workflows.py","shell_tools.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-4869-x4pr-q22x: PraisonAI: Unauthenticated RCE via Jobs A
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("yaml_parser.py", "workflows.py", "shell_tools.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("yaml_parser.py", "workflows.py", "shell_tools.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
