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
- **T1078** — Valid Accounts (bypass via missing auth)
- **T1059.004** — Unix Shell
- **T1059.003** — Windows Command Shell
- **T1105** — Ingress Tool Transfer
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI unauthenticated Jobs API request (POST /api/v1/runs)

`UC_49_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agent values(Web.src) as src values(Web.url) as url from datamodel=Web.Web where Web.http_method=POST (Web.url="*/api/v1/runs*" OR Web.dest_port=8005) by Web.dest Web.src Web.url
| `drop_dm_object_name(Web)`
| regex src="^(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.0\.0\.1).+"
| where count >= 1
```

**Defender KQL:**
```kql
// Defender lacks raw HTTP body — pivot on inbound TCP to the Jobs API port from a public source where the listening process is the praisonai/uvicorn runtime.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 8005
| where ActionType in ("InboundConnectionAccepted", "ConnectionAccepted", "ListeningConnectionCreated")
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","uvicorn","uvicorn.exe","gunicorn")
   or InitiatingProcessCommandLine has_any ("praisonai","praisonai.jobs","uvicorn")
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId
| order by Timestamp desc
```

### PraisonAI workflow runtime spawning shell/curl/wget child (RCE manifestation)

`UC_49_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.process_id) as process_id from datamodel=Endpoint.Processes where (Processes.parent_process_name="python*" OR Processes.parent_process_name="uvicorn*" OR Processes.parent_process_name="gunicorn*") Processes.parent_process="*praisonai*" (Processes.process_name="curl*" OR Processes.process_name="wget*" OR Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash" OR Processes.process_name="zsh" OR Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh" OR Processes.process_name="nc" OR Processes.process_name="ncat" OR Processes.process_name="socat") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python","python3","python3.exe","uvicorn","uvicorn.exe","gunicorn")
| where InitiatingProcessCommandLine has_any ("praisonai","praisonai.jobs","praisonaiagents","praisonai/api","uvicorn")
| where FileName in~ ("curl","curl.exe","wget","wget.exe","sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh","pwsh.exe","nc","ncat","socat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Unexpected egress from PraisonAI host to non-LLM destination

`UC_49_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="python*" OR All_Traffic.process_name="uvicorn*" OR All_Traffic.process_name="gunicorn*" OR All_Traffic.process_name="curl*" OR All_Traffic.process_name="wget*") (All_Traffic.dest_category!="internal" AND NOT All_Traffic.dest_host IN ("api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","cognitiveservices.azure.com","openai.azure.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let LlmAllowList = dynamic(["api.openai.com","api.anthropic.com","generativelanguage.googleapis.com","cognitiveservices.azure.com","openai.azure.com","huggingface.co","models.googleapis.com","bedrock-runtime.amazonaws.com","ollama.ai","groq.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName in~ ("python","python.exe","python3","python3.exe","uvicorn","gunicorn") and InitiatingProcessCommandLine has_any ("praisonai","uvicorn","praisonaiagents"))
   or (InitiatingProcessParentFileName in~ ("python","python.exe","python3","python3.exe","uvicorn","gunicorn") and InitiatingProcessFileName in~ ("curl","curl.exe","wget","wget.exe","sh","bash","nc","ncat"))
| where RemoteIPType == "Public"
| where isempty(RemoteUrl) or not(RemoteUrl has_any (LlmAllowList))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-4869-x4pr-q22x: PraisonAI: Unauthenticated RCE via Jobs A

`UC_49_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
