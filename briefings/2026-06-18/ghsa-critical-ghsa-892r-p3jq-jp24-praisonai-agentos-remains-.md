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
- **T1213** — Data from Information Repositories
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PraisonAI AgentOS unauthenticated POST /api/chat remote agent invocation

`UC_68_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as request_count, values(Web.http_user_agent) as user_agent, values(Web.status) as status, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where (Web.uri_path="/api/chat" OR Web.uri_path="/api/agents") (Web.http_method="POST" OR Web.http_method="GET") by Web.src, Web.dest, Web.uri_path, Web.http_method
| `drop_dm_object_name(Web)`
| where status=200
| sort - request_count
```

### PraisonAI AgentOS process bound to 0.0.0.0:8000 / external inbound connections

`UC_68_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Processes.process) as process, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*praisonai*" OR Processes.process="*agentos*" OR Processes.process="*AgentApp*") (Processes.process="*0.0.0.0*" OR Processes.process="*8000*") by Processes.dest, Processes.user, Processes.process_name, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 8000
| where RemoteIPType == "Public"
| where InitiatingProcessFileName has_any ("python","python3","python.exe","python3.exe","uvicorn","gunicorn")
| where InitiatingProcessCommandLine has_any ("praisonai","agentos","AgentApp","AgentOS")
| summarize ConnCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), RemoteIPs=make_set(RemoteIP, 100) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, LocalPort
| order by FirstSeen desc
```

### Vulnerable PraisonAI package inventory (CVE-2026-40151, >= 4.2.1 <= 4.6.57)

`UC_68_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "praisonai" or SoftwareName has "praisonaiagents"
| extend Vuln = iff(SoftwareVersion matches regex @"^4\.([2-5]\.|6\.([0-9]|[0-5][0-9])$)", "in-vulnerable-range(>=4.2.1,<=4.6.57)", "verify-version")
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, Vuln, EndOfSupportStatus
| sort by DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40151`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
