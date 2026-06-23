# [CRIT] [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Critical Function and Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in praiso

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-p75f-6fp4-p57w

## Threat Profile

PraisonAI: Missing Authentication for Critical Function and Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in praisonai

# Unauthenticated PraisonAI UI MCP connect endpoint executes attacker-chosen local commands

## Summary

PraisonAI v4.6.48 exposes the PraisonAIUI MCP client management API through the default UI host apps without authentication. A remote unauthenticated client can send `POST /api/mcp/connect` with a `command` and `args` field. The e…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI UI (aiui) server spawns shell/LOLBin child via unauth MCP connect RCE

`UC_85_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process="*aiui run*" OR Processes.parent_process="*praisonai ui*" OR Processes.parent_process="*praisonai claw*" OR Processes.parent_process="*create_host_app*") AND (Processes.process_name IN ("sh","bash","dash","zsh","ksh","fish","busybox","touch","curl","wget","nc","ncat","socat","chmod","base64","whoami","id","uname","cmd.exe","powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has_any ("aiui run","praisonai ui","praisonai claw","create_host_app","build_host_app") or InitiatingProcessFileName =~ "aiui"
| where FileName in~ ("sh","bash","dash","zsh","ksh","fish","busybox","touch","curl","wget","nc","ncat","socat","chmod","base64","whoami","id","uname","cmd.exe","powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe")
| where not (FileName in~ ("curl","wget") and ProcessCommandLine has_any ("registry.npmjs.org","pypi.org","ghcr.io","objects.githubusercontent.com"))
| project Timestamp, DeviceName, AccountName, ParentCmd = InitiatingProcessCommandLine, ParentImage = InitiatingProcessFolderPath, ChildImage = FolderPath, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Unauthenticated POST to PraisonAI /api/mcp/connect MCP endpoint

`UC_85_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/mcp/connect*" OR Web.url="*/api/mcp/servers*") AND Web.http_method="POST" by Web.src Web.dest Web.dest_port Web.url Web.http_method Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### PraisonAI MCP RCE proof-of-concept marker file written to /tmp

`UC_85_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("praisonai_host_app_mcp_touch_marker.txt","pwned-by-ui-mcp") OR Filesystem.file_path IN ("/tmp/praisonai_host_app_mcp_touch_marker.txt","/tmp/pwned-by-ui-mcp")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("praisonai_host_app_mcp_touch_marker.txt","pwned-by-ui-mcp") or FolderPath in~ ("/tmp/praisonai_host_app_mcp_touch_marker.txt","/tmp/pwned-by-ui-mcp")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Cri

`UC_85_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Cri ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("aiui-mcp-connect-rce.py","server.py","mcp.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/touch*" OR Filesystem.file_path="*/tmp/praisonai_host_app_mcp_touch_marker.txt*" OR Filesystem.file_path="*/tmp/pwned-by-ui-mcp*" OR Filesystem.file_name IN ("aiui-mcp-connect-rce.py","server.py","mcp.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p75f-6fp4-p57w: PraisonAI: Missing Authentication for Cri
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("aiui-mcp-connect-rce.py", "server.py", "mcp.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/touch", "/tmp/praisonai_host_app_mcp_touch_marker.txt", "/tmp/pwned-by-ui-mcp") or FileName in~ ("aiui-mcp-connect-rce.py", "server.py", "mcp.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
