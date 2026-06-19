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
- **T1485** — Data Destruction
- **T1531** — Account Access Removal
- **T1087** — Account Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### praisonai-platform admin DELETE on /workspaces or /{workspace}/members endpoints

`UC_32_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.status) as status values(Web.user) as user from datamodel=Web where Web.http_method="DELETE" (Web.url="*/workspaces/*" OR Web.url="*/members/*") Web.status>=200 Web.status<300 by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | rex field=url "/workspaces/(?<workspace_id>[0-9a-fA-F-]{36})$|/(?<workspace_id2>[0-9a-fA-F-]{36})/members/(?<member_id>[0-9a-fA-F-]{36})$" | where isnotnull(workspace_id) OR isnotnull(workspace_id2) | eval target_workspace=coalesce(workspace_id, workspace_id2) | sort - lastTime
```

### praisonai-platform attack chain: member enumeration GET followed by workspace-delete

`UC_32_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Web where Web.http_method IN ("GET","DELETE") (Web.url="*/members*" OR Web.url="*/workspaces/*") by _time Web.src Web.url Web.http_method Web.status Web.user span=1s | `drop_dm_object_name(Web)` | rex field=url "(?<workspace_id>[0-9a-fA-F-]{36})" | where isnotnull(workspace_id) | eval action=case(http_method="GET" AND like(url,"%/members"),"enum", http_method="DELETE" AND match(url,"/workspaces/[0-9a-fA-F-]{36}/?$"),"delete_ws", http_method="DELETE" AND match(url,"/[0-9a-fA-F-]{36}/members/[0-9a-fA-F-]{36}/?$"),"delete_member") | where isnotnull(action) | stats earliest(eval(if(action="enum",_time,null))) as enum_time latest(eval(if(action IN ("delete_ws","delete_member"),_time,null))) as destruct_time values(action) as actions values(url) as urls values(src) as srcs values(user) as users by workspace_id | where isnotnull(enum_time) AND isnotnull(destruct_time) AND destruct_time-enum_time<=1800 AND destruct_time>=enum_time | eval delay_sec=destruct_time-enum_time | sort - destruct_time
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-f38v-77qj-h4jq: praisonai-platform 0.1.4 still boots on t

`UC_32_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
