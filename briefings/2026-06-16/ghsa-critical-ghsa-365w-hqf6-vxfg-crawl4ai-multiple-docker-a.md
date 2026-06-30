# [CRIT] [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabilities - File Write, SSRF, Auth Bypass, XSS, JS Execution

**Source:** GitHub Security Advisories
**Published:** 2026-06-16
**Article:** https://github.com/advisories/GHSA-365w-hqf6-vxfg

## Threat Profile

Crawl4AI: Multiple Docker API Vulnerabilities - File Write, SSRF, Auth Bypass, XSS, JS Execution

### Summary

Multiple security vulnerabilities in the Crawl4AI Docker API server affecting endpoints for crawling, markdown/LLM extraction, screenshots, PDFs, webhooks, monitoring, JavaScript execution, and configuration.

### Vulnerabilities

#### 1. Arbitrary File Write via /screenshot and /pdf (CWE-22, CVSS 9.1)

The `output_path` parameter accepts arbitrary filesystem paths with no validation. A…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1053.003** — Scheduled Task/Job: Cron
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1046** — Network Service Discovery
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1485** — Data Destruction
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI /screenshot or /pdf output_path traversal → arbitrary file write outside output dir

`UC_168_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path IN ("/etc/*","/root/*","/etc/cron*","*/.ssh/*","*authorized_keys*","*/.bashrc","*/.profile","/usr/local/*","/app/*")) AND NOT Filesystem.file_path="/tmp/crawl4ai-outputs/*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName matches regex @"(?i)^(python[0-9.]*|uvicorn|gunicorn)$"
| where FolderPath !startswith "/tmp/crawl4ai-outputs"
| where FolderPath has_any ("/etc/","/root/","/etc/cron","/.ssh","authorized_keys","/.bashrc","/.profile","/usr/local/","/app/")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Crawl4AI SSRF: crawler process reaching cloud-metadata or RFC1918 internal IPs

`UC_168_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("169.254.169.254","::ffff:169.254.169.254") AND All_Traffic.app IN ("python","python3","uvicorn","gunicorn","chromium","chrome","node") by All_Traffic.src All_Traffic.app All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName matches regex @"(?i)^(python[0-9.]*|uvicorn|gunicorn|chromium|chrome|headless_shell|node)$"
| extend MetadataHit = (RemoteIP == "169.254.169.254" or RemoteIP == "::ffff:169.254.169.254")
| where MetadataHit or ipv4_is_private(RemoteIP) or ipv4_is_in_range(RemoteIP, "169.254.0.0/16")
| extend Severity = iff(MetadataHit, "CRITICAL-cloud-metadata", "internal-SSRF")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Severity
| order by Severity asc, Timestamp desc
```

### Crawl4AI /execute_js sandbox escape: crawler/browser process spawning a shell

`UC_168_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python3","uvicorn","gunicorn","node","chromium","chrome","headless_shell")) AND (Processes.process_name IN ("sh","bash","dash","zsh","ash")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName matches regex @"(?i)^(python[0-9.]*|uvicorn|gunicorn|node|chromium|chrome|headless_shell)$"
| where FileName in~ ("sh","bash","dash","zsh","ash","cmd.exe","powershell.exe","pwsh")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Crawl4AI unauthenticated access to /monitor endpoints (auth bypass)

`UC_168_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url IN ("*/monitor/actions/cleanup*","*/monitor/actions*","*/monitor/ws*","*/monitor/*")) AND Web.status IN ("200","101","204") by Web.src Web.http_method Web.url Web.status Web.http_user_agent Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

### Crawl4AI web-payload abuse: path traversal, XSS, file:// and metadata-IP in crawl requests

`UC_168_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url IN ("*/screenshot*","*/pdf*","*/crawl*","*/md*","*/llm*","*/execute_js*","*/markdown_extraction*","*/llm_extraction*")) AND (Web.url IN ("*../*","*..%2f*","*%2e%2e*","*<script*","*onerror=*","*onclick=*","*file://*","*169.254.169.254*","*::ffff:*","*metadata.google*","*output_path=*")) by Web.src Web.http_method Web.url Web.status Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili

`UC_168_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/crawl4ai-outputs*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/crawl4ai-outputs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
