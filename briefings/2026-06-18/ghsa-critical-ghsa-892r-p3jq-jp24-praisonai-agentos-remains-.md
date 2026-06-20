# [CRIT] [GHSA / CRITICAL] GHSA-892r-p3jq-jp24: PraisonAI: AgentOS remains unauthenticated after incomplete fix version and allows remote agent invocation

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-892r-p3jq-jp24

## Threat Profile

PraisonAI: AgentOS remains unauthenticated after incomplete fix version and allows remote agent invocation

# AgentOS remains unauthenticated after GHSA-pm96 patched version and allows remote agent invocation

## Summary

PraisonAI's `AgentOS` FastAPI deployment surface remains unauthenticated in
current main and in releases after the published patched version for
`GHSA-pm96-6xpr-978x` / `CVE-2026-40151`.

The public AgentOS advisory is published as an instruction-disclosure issue
with affected …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-40151`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1526** — Cloud Service Discovery
- **T1059** — Command and Scripting Interpreter
- **T1657** — Financial Theft
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated GET /api/agents or /agents enumeration probe

`UC_56_1` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src values(Web.user_agent) as user_agent values(Web.status) as status from datamodel=Web.Web where Web.url="*/api/agents*" Web.http_method="GET" Web.status=200 by Web.dest Web.src | `drop_dm_object_name(Web)` | search NOT (src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) | where NOT match(user_agent,"(?i)praisonai|internal-monitor") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("/api/agents", "/agents")
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","uvicorn.exe","gunicorn","pwsh.exe","powershell.exe","curl.exe","wget.exe")
| where RemotePort in (8000, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### Unauthenticated POST /api/chat triggering remote agent invocation

`UC_56_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user_agent) as user_agent values(Web.status) as status values(Web.http_user_agent) as ua from datamodel=Web.Web where Web.url="*/api/chat*" Web.http_method="POST" Web.status=200 by Web.dest Web.src Web.dest_port | `drop_dm_object_name(Web)` | where dest_port=8000 OR match(url,"(?i)/api/chat") | search NOT (src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "/api/chat"
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","uvicorn.exe","gunicorn","curl.exe","wget.exe","pwsh.exe","powershell.exe")
| where RemotePort in (8000, 80, 443)
| extend IsHighRiskParent = InitiatingProcessParentFileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl, IsHighRiskParent
| order by Timestamp desc
```

### PraisonAI AgentOS process bound to 0.0.0.0 on default port 8000

`UC_56_3` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("python.exe","python3","python","uvicorn.exe","uvicorn","gunicorn") (Processes.process="*agentos*" OR Processes.process="*AgentApp*" OR Processes.process="*praisonai*") Processes.process="*0.0.0.0*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("python.exe","python3.exe","uvicorn.exe","gunicorn")
| where ProcessCommandLine has_any ("agentos", "AgentApp", "praisonai")
| where ProcessCommandLine has "0.0.0.0" or ProcessCommandLine has "--host=0.0.0.0" or ProcessCommandLine has "host='0.0.0.0'"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40151`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
