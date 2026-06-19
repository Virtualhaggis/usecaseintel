# [CRIT] [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on the hardcoded JWT secret dev-secret-change-me (default-open production guard)

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-f38v-77qj-h4jq

## Threat Profile

praisonai-platform 0.1.4 still boots on the hardcoded JWT secret dev-secret-change-me (default-open production guard)

- Affected: praisonai-platform (PyPI) <= 0.1.4 — including 0.1.4, the version GHSA-3qg8-5g3r-79v5 declares as the patch; main HEAD 8acf77c531e624c46d3d61dcae37e9942e90972c is also affected. File src/praisonai-platform/praisonai_platform/services/auth_service.py

- CWE: CWE-1188 (Insecure Default Initialization) + CWE-798 (Use of Hard-coded Credentials) -> CWE-287 (Improper Authe…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `cc29d43c5412da2c73c818859b8d8b146587842999b777336017ab9d9e509258`
- **SHA1:** `8acf77c531e624c46d3d61dcae37e9942e90972c`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1087.004** — Account Discovery: Cloud Account
- **T1213** — Data from Information Repositories
- **T1485** — Data Destruction
- **T1531** — Account Access Removal

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable praisonai-platform server launch (GHSA-f38v-77qj-h4jq / CVE-2026-47410)

`UC_25_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="*praisonai_platform.api.app:app*" OR Processes.process="*-m praisonai_platform*" OR Processes.process="*praisonai_platform --host*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","python3.exe","python","uvicorn","uvicorn.exe","gunicorn") or FileName in~ ("python.exe","python3","python3.exe","python","uvicorn","uvicorn.exe","gunicorn")
| where ProcessCommandLine has_any ("praisonai_platform.api.app:app", "-m praisonai_platform", "praisonai_platform --host")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### praisonai-platform workspace-member enumeration fan-out (forged-JWT recon)

`UC_25_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Web.url) as workspaces_enumerated, min(_time) as firstTime, max(_time) as lastTime, values(Web.user_agent) as user_agents, values(Web.url) as sample_urls from datamodel=Web.Web where Web.http_method="GET" Web.url="*/members" Web.url="*-*-*-*-*/members" by Web.src Web.user | `drop_dm_object_name(Web)` | where workspaces_enumerated >= 5 | convert ctime(firstTime) ctime(lastTime)
```

### praisonai-platform workspace / member destructive DELETE (forged-JWT impact)

`UC_25_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user_agent) as agents values(Web.status) as statuses from datamodel=Web.Web where Web.http_method="DELETE" (Web.url="*/workspaces/*" OR Web.url="*/members/*") by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | where match(urls, "/workspaces/[0-9a-f-]{36}") OR match(urls, "/[0-9a-f-]{36}/members/[0-9a-f-]{36}") | convert ctime(firstTime) ctime(lastTime)
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on t

`UC_25_1` · phase: **exploit** · confidence: **High**

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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `cc29d43c5412da2c73c818859b8d8b146587842999b777336017ab9d9e509258`, `8acf77c531e624c46d3d61dcae37e9942e90972c`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
