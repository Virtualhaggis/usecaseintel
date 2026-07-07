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
- **T1190** — Exploit Public-Facing Application
- **T1659** — Content Injection
- **T1213** — Data from Information Repositories
- **T1485** — Data Destruction
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059** — Command and Scripting Interpreter
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated POST to PraisonAI Jobs API /api/v1/runs (agent-exec RCE entry)

`UC_231_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly count, min(_time) as firstTime, max(_time) as lastTime, values(Web.status) as status, values(Web.http_user_agent) as user_agent from datamodel=Web where Web.http_method=POST (Web.uri_path="/api/v1/runs" OR Web.url="*/api/v1/runs") by Web.src, Web.dest, Web.dest_port, Web.uri_path, Web.http_method
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| eval queued=if(like(status,"%202%"),"yes","no")
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 8005
| where RemoteIPType == "Public"
| where InitiatingProcessFileName has_any ("python","python3","python.exe","uvicorn","gunicorn")
| where InitiatingProcessCommandLine has_any ("praisonai.jobs.server","praisonai","jobs.server")
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Connections desc
```

### PraisonAI Jobs API mass enumeration & result harvesting (/api/v1/runs list + read + delete)

`UC_231_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly count, dc(Web.uri_path) as distinct_job_paths, values(Web.http_method) as methods, count(eval(Web.http_method="DELETE")) as delete_count, count(eval(Web.http_method="GET")) as get_count from datamodel=Web where (Web.uri_path="/api/v1/runs" OR Web.uri_path="/api/v1/runs/*") (Web.http_method=GET OR Web.http_method=DELETE OR Web.http_method=POST) by Web.src, Web.dest, span=10m
| `drop_dm_object_name(Web)`
| where count > 50 OR distinct_job_paths > 20 OR delete_count > 5   // 50 req / 20 distinct job-ids / 5 deletes per 10m: legit backend polling stays well under this from a single IP
| sort - count
```

### PraisonAI jobs server (praisonai.jobs.server) spawning shell / network child process

`UC_231_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly count, values(Endpoint.Processes.process) as child_cmdline, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Endpoint.Processes.parent_process="*praisonai.jobs.server*" (Endpoint.Processes.process_name="sh" OR Endpoint.Processes.process_name="bash" OR Endpoint.Processes.process_name="dash" OR Endpoint.Processes.process_name="zsh" OR Endpoint.Processes.process_name="cmd.exe" OR Endpoint.Processes.process_name="powershell.exe" OR Endpoint.Processes.process_name="pwsh" OR Endpoint.Processes.process_name="curl" OR Endpoint.Processes.process_name="wget" OR Endpoint.Processes.process_name="nc" OR Endpoint.Processes.process_name="ncat") by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.parent_process, Endpoint.Processes.process_name
| `drop_dm_object_name(Endpoint.Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has "praisonai.jobs.server"
| where FileName in~ ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","curl","wget","nc","ncat","python","python3")
| where not (FileName in~ ("python","python3") and ProcessCommandLine has "pip")   // drop in-runtime pip installs
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Exposed PraisonAI jobs server bound to 0.0.0.0 (praisonai.jobs.server --host=0.0.0.0)

`UC_231_4` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly count, min(_time) as firstTime, max(_time) as lastTime, values(Endpoint.Processes.process) as cmdline from datamodel=Endpoint.Processes where Endpoint.Processes.process="*praisonai.jobs.server*" Endpoint.Processes.process="*0.0.0.0*" by Endpoint.Processes.dest, Endpoint.Processes.user, Endpoint.Processes.process_name
| `drop_dm_object_name(Endpoint.Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "praisonai.jobs.server"
| where ProcessCommandLine has "0.0.0.0"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), arg_max(Timestamp, ProcessCommandLine, FileName, FolderPath) by DeviceName, DeviceId, AccountName
| order by LastSeen desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-fq2m-6wqh-x44g: PraisonAI: Jobs API exposes agent-executi

`UC_231_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
