# [CRIT] [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal

**Source:** GitHub Security Advisories
**Published:** 2026-06-23
**Article:** https://github.com/advisories/GHSA-phv5-334h-mxcw

## Threat Profile

motionEye Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal

# Partial Authentication Bypass: Unauthenticated Admin Credential Theft via Path Traversal

### Summary

Myself and others have reported several RCE vulnerabilities to this project. However, due to the nature of the app, these are largely not of all that much value, as there is built-in functionality to run commands upon certain actions — i.e. RCE is by design.

With that in mind, I endeavored to …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-55488`
- **CVE:** `CVE-2026-32315`
- **CVE:** `CVE-2026-46488`
- **CVE:** `CVE-2026-31978`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### motionEye unauthenticated path traversal read of motion.conf / system secrets

`UC_278_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_method="GET" AND (Web.url="*/playback/*" OR Web.url="*/download/*" OR Web.url="*/preview/*") AND (Web.url="*motion.conf*" OR Web.url="*/etc/passwd*" OR Web.url="*/etc/shadow*" OR Web.url="*/etc/*" OR Web.url="*/root/*" OR Web.url="*.ssh*")) by Web.src Web.dest Web.http_method Web.url Web.status
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### motionEye RCE: motion daemon spawns shell via injected command_*_exec hook

`UC_278_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="motion" AND (Processes.process_name="sh" OR Processes.process_name="bash" OR Processes.process_name="dash" OR Processes.process_name="curl" OR Processes.process_name="wget" OR Processes.process_name="nc" OR Processes.process_name="python" OR Processes.process_name="python3" OR Processes.process_name="perl") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "motion"
| where FileName in~ ("sh","bash","dash","curl","wget","nc","ncat","python","python3","perl","touch")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### motionEye traversal read followed by admin config-hook write from same source

`UC_278_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as reads from datamodel=Web where (Web.http_method="GET" AND (Web.url="*/playback/*" OR Web.url="*/download/*" OR Web.url="*/preview/*") AND (Web.url="*motion.conf*" OR Web.url="*/etc/*")) by Web.src
| `drop_dm_object_name(Web)`
| join type=inner src [
    | tstats `summariesonly` count as writes from datamodel=Web where (Web.http_method="POST" AND Web.url="*/config/*/set*") by Web.src
    | `drop_dm_object_name(Web)` ]
| where reads>0 AND writes>0
| table src reads writes
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass:

`UC_278_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass: ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("config.py","mediafiles.py","movie_playback.py","base.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/motioneye/motion.conf*" OR Filesystem.file_path="*/tmp/pwned*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_name IN ("config.py","mediafiles.py","movie_playback.py","base.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-phv5-334h-mxcw: motionEye Partial Authentication Bypass:
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("config.py", "mediafiles.py", "movie_playback.py", "base.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/motioneye/motion.conf", "/tmp/pwned", "/etc/passwd", "/etc/shadow") or FileName in~ ("config.py", "mediafiles.py", "movie_playback.py", "base.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-55488`, `CVE-2026-32315`, `CVE-2026-46488`, `CVE-2026-31978`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
