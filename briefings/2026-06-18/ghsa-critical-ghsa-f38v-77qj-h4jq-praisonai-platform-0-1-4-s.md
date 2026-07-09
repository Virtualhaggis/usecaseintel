# [CRIT] [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on the hardcoded JWT secret dev-secret-change-me (default-open production guard)

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-f38v-77qj-h4jq

## Threat Profile

praisonai-platform 0.1.4 still boots on the hardcoded JWT secret dev-secret-change-me (default-open production guard)

- Affected: praisonai-platform (PyPI) <= 0.1.4 — including 0.1.4, the version GHSA-3qg8-5g3r-79v5 declares as the patch; main HEAD 8acf77c531e624c46d3d61dcae37e9942e90972c is also affected. File src/praisonai-platform/praisonai_platform/services/auth_service.py

- CWE: CWE-1188 (Insecure Default Initialization) + CWE-798 (Use of Hard-coded Credentials) -> CWE-287 (Improper Authe…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-47410`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1078** — Valid Accounts
- **T1485** — Data Destruction
- **T1531** — Account Access Removal
- **T1606** — Forge Web Credentials
- **T1087** — Account Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-facing PraisonAI platform booting on default JWT secret (CVE-2026-47410)

`UC_234_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*praisonai_platform*" AND Processes.process="*0.0.0.0*" by Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "praisonai_platform"
| where ProcessCommandLine has_any ("uvicorn", "-m praisonai_platform", "praisonai_platform.api.app")
| where ProcessCommandLine has "0.0.0.0"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### PraisonAI workspace/member destruction via owner-gated routes (forged-JWT takeover impact)

`UC_234_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method="DELETE" (Web.uri_path="/workspaces/*" OR Web.uri_path="*/members/*") Web.status>=200 Web.status<300 by Web.src, Web.user, Web.http_method, Web.uri_path, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)`
```

### PraisonAI workspace member enumeration harvesting owner user_ids (pre-takeover recon)

`UC_234_4` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Web.uri_path) as workspaces_enumerated count from datamodel=Web.Web where Web.http_method="GET" Web.uri_path="*/members" Web.status>=200 Web.status<300 by Web.src, Web.user, _time span=10m | `drop_dm_object_name(Web)` | where workspaces_enumerated >= 5
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on t

`UC_234_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on t ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("deps.py","poc.py","auth_service.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("deps.py","poc.py","auth_service.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on t
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("deps.py", "poc.py", "auth_service.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("deps.py", "poc.py", "auth_service.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-47410`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
