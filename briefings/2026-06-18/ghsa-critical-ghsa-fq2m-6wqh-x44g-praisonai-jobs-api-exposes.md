# [CRIT] [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-execution endpoints with no authentication

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-fq2m-6wqh-x44g

## Threat Profile

PraisonAI: Jobs API exposes agent-execution endpoints with no authentication

# praisonai: Jobs API exposes agent-execution endpoints with no authentication

**Researcher:** Kai Aizen — SnailSploit (@SnailSploit), Adversarial & Offensive Security Research 
**Target:** https://github.com/MervinPraison/PraisonAI

---

**Package:** `praisonai` on PyPI
**Affected version (empirically tested):** 4.6.48
**Components:**
- `praisonai.jobs.server.create_app` — `praisonai/jobs/server.py`
- `praisonai.jobs…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1133** — External Remote Services
- **T1190** — Exploit Public-Facing Application
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059** — Command and Scripting Interpreter
- **T1059.001** — PowerShell
- **T1059.004** — Unix Shell
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI Jobs API server bound to 0.0.0.0 (GHSA-fq2m-6wqh-x44g exposure)

`UC_58_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=python.exe OR Processes.process_name=python OR Processes.process_name=python3 OR Processes.process_name=python3.exe) Processes.process="*praisonai.jobs.server*" (Processes.process="*--host=0.0.0.0*" OR Processes.process="*--host 0.0.0.0*" OR Processes.process="* -h 0.0.0.0*" OR Processes.process="*--host=::*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe","python","python3","python3.exe","pythonw.exe")
| where ProcessCommandLine has "praisonai.jobs.server"
| where ProcessCommandLine has_any ("--host=0.0.0.0","--host 0.0.0.0"," -h 0.0.0.0","--host=::","--host ::")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, ProcessCommandLine, ProcessId
| order by Timestamp desc
```

### Unauthenticated POST to PraisonAI /api/v1/runs (GHSA-fq2m-6wqh-x44g exploitation)

`UC_58_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.status) as status values(Web.http_method) as method values(Web.src) as src from datamodel=Web.Web where Web.url="*/api/v1/runs*" Web.http_method=POST by Web.dest Web.url Web.user_agent | `drop_dm_object_name(Web)` | where isnull(mvfind(mvappend(method), "")) OR mvcount(method)>0 | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 8005
| where RemoteIPType in ("Public","Internet")
| where InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","pythonw.exe")
| where InitiatingProcessCommandLine has "praisonai.jobs.server"
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Ports=make_set(LocalPort), Sample=any(InitiatingProcessCommandLine) by DeviceName, RemoteIP, InitiatingProcessFileName
| order by LastSeen desc
```

### PraisonAI executor child-process spawn (post-RCE via agent tool invocation)

`UC_58_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.parent_process="*praisonai*" (Processes.process_name IN (cmd.exe,powershell.exe,pwsh.exe,bash,sh,zsh,dash,wscript.exe,cscript.exe,mshta.exe) OR Processes.process IN ("*curl *","*wget *","*nc *","*ncat *","*/bin/sh*","*/bin/bash*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has_any ("praisonai","crewai","autogen") and InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","pythonw.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","zsh","dash","wscript.exe","cscript.exe","mshta.exe","curl","curl.exe","wget","wget.exe","nc","ncat","socat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, ProcessId
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi

`UC_58_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("server.py","router.py","executor.py","poc.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("server.py","router.py","executor.py","poc.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("server.py", "router.py", "executor.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("server.py", "router.py", "executor.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
