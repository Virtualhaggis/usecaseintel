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
- **T1133** — External Remote Services
- **T1078** — Valid Accounts
- **T1106** — Native API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI AgentOS launched with 0.0.0.0 bind exposing unauthenticated /api/chat (CVE-2026-40151)

`UC_28_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as process_cmdline, values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("python.exe","python3.exe","python3","pythonw.exe","uvicorn.exe","uvicorn") AND (Processes.process LIKE "%praisonai%" OR Processes.process LIKE "%AgentApp%" OR Processes.process LIKE "%AgentOS%" OR Processes.process LIKE "%agentos%") AND (Processes.process LIKE "%0.0.0.0%" OR Processes.process LIKE "%--host 0.0.0.0%" OR Processes.process LIKE "%host=0.0.0.0%") by Processes.dest, Processes.user, Processes.process_name | `drop_dm_object_name(Processes)` | where NOT match(process_cmdline, "(?i)127\.0\.0\.1") | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe","python3.exe","pythonw.exe","uvicorn.exe","python","python3","uvicorn")
| where ProcessCommandLine has_any ("praisonai","AgentApp","AgentOS","agentos","AgentOSConfig","AgentAppConfig")
| where ProcessCommandLine has "0.0.0.0"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Unauthenticated POST to PraisonAI /api/chat from external network (CVE-2026-40151 exploitation)

`UC_28_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Web.user_agent) as user_agents, values(Web.http_method) as methods, values(Web.url) as urls from datamodel=Web.Web where (Web.url="*/api/chat*" OR Web.url="*/api/agents*") AND Web.dest_port=8000 AND NOT (Web.src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.1")) by Web.src_ip, Web.dest, Web.url, Web.http_method, Web.status | `drop_dm_object_name(Web)` | where status=200 OR isnull(status)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess","InboundConnectionRequest")
| where LocalPort == 8000
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","uvicorn.exe")
| where InitiatingProcessCommandLine has_any ("praisonai","AgentApp","AgentOS","agentos")
| where RemoteIPType == "Public"
| summarize HitCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SamplePid = any(InitiatingProcessId)
         by DeviceName, RemoteIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by LastSeen desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40151`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
