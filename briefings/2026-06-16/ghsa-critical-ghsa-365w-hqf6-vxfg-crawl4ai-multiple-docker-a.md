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
- **T1552.005** — Cloud Instance Metadata API
- **T1090** — Proxy
- **T1190** — Exploit Public-Facing Application
- **T1083** — File and Directory Discovery
- **T1059.007** — JavaScript
- **T1059.004** — Unix Shell
- **T1059.001** — PowerShell
- **T1485** — Data Destruction
- **T1027** — Obfuscated Files or Information
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI Python process outbound to cloud-metadata IP 169.254.169.254 (SSRF exploitation)

`UC_43_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic where All_Traffic.dest_ip IN ("169.254.169.254","fd00:ec2::254") (All_Traffic.process_name="python*" OR All_Traffic.process_name="uvicorn*" OR All_Traffic.process_name="gunicorn*" OR All_Traffic.app="crawl4ai*") by host All_Traffic.src All_Traffic.dest_ip All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIP in ("169.254.169.254", "fd00:ec2::254")
| where InitiatingProcessFileName has_any ("python", "python3", "python3.10", "python3.11", "python3.12", "uvicorn", "gunicorn")
   or InitiatingProcessCommandLine has_any ("crawl4ai", "crawl4ai_server", "crawl4ai-serve")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### Path traversal in Crawl4AI /screenshot or /pdf output_path parameter

`UC_43_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.status) as status values(Web.http_method) as http_method values(Web.url) as url from datamodel=Web where (Web.uri_path="*/screenshot*" OR Web.uri_path="*/pdf*") (Web.url="*output_path=*..*" OR Web.url="*output_path=%2F*" OR Web.url="*output_path=/etc/*" OR Web.url="*output_path=/root/*" OR Web.url="*output_path=/var/spool/cron*" OR Web.url="*output_path=*.ssh*" OR Web.url="*%2e%2e%2f*") by host Web.src Web.dest Web.user | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("/screenshot", "/pdf")
| where RemoteUrl has "output_path"
| where RemoteUrl has_any ("..", "%2e%2e", "/etc/", "/root/", "/var/spool/cron", ".ssh", "/proc/", "/.bashrc", "/.profile", "crontab")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, LocalIP
| order by Timestamp desc
```

### Crawl4AI Python/uvicorn server spawns shell child (post-/execute_js RCE)

`UC_43_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.parent_process_name="python*" OR Processes.parent_process_name="uvicorn*" OR Processes.parent_process_name="gunicorn*" OR Processes.parent_process="*crawl4ai*") (Processes.process_name IN ("bash","sh","dash","zsh","ksh","cmd.exe","powershell.exe","pwsh.exe")) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName has_any ("python", "python3", "uvicorn", "gunicorn")
   or InitiatingProcessCommandLine has "crawl4ai"
| where FileName in~ ("bash", "sh", "dash", "zsh", "ksh", "cmd.exe", "powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, AccountName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Unauthenticated access to Crawl4AI /monitor destructive endpoints

`UC_43_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.status) as status values(Web.http_user_agent) as ua values(Web.http_method) as method from datamodel=Web where Web.uri_path IN ("/monitor/actions/cleanup","/monitor/ws","/monitor/jobs","/monitor/stats","/monitor/health") Web.status IN (200,101) by host Web.src Web.uri_path Web.user | `drop_dm_object_name(Web)` | where !match(src, "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("/monitor/actions/cleanup", "/monitor/ws", "/monitor/jobs", "/monitor/stats")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Crawl4AI SSRF via IPv6-mapped IPv4 bypass pattern in /crawl, /md, /llm request

`UC_43_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method from datamodel=Web where (Web.uri_path="*/crawl*" OR Web.uri_path="*/md*" OR Web.uri_path="*/llm*") (Web.url="*::ffff:*" OR Web.url="*%3A%3Affff%3A*" OR Web.url="*[::ffff:*") by host Web.src Web.uri_path Web.user | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("/crawl", "/md", "/llm")
| where RemoteUrl has_any ("::ffff:", "%3A%3Affff%3A", "[::ffff:")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Crawl4AI writes file outside /tmp/crawl4ai-outputs (output_path traversal landing)

`UC_43_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as action values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.process_name="python*" OR Filesystem.process_name="uvicorn*" OR Filesystem.process_name="gunicorn*" OR Filesystem.process="*crawl4ai*") Filesystem.action="created" (Filesystem.file_path="/etc/*" OR Filesystem.file_path="/root/*" OR Filesystem.file_path="/var/spool/cron*" OR Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="/usr/local/bin/*" OR Filesystem.file_path="/home/*/.bashrc") by host Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName has_any ("python", "python3", "uvicorn", "gunicorn")
   or InitiatingProcessCommandLine has "crawl4ai"
| where not(FolderPath startswith "/tmp/crawl4ai-outputs" or FolderPath startswith "/tmp/playwright" or FolderPath startswith "/tmp/.cache")
| where FolderPath startswith "/etc/"
    or FolderPath startswith "/root/"
    or FolderPath startswith "/var/spool/cron"
    or FolderPath has "/.ssh/"
    or FolderPath startswith "/usr/local/bin/"
    or FolderPath has "/.bashrc"
    or FolderPath has "/.profile"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Crawl4AI /crawl/job or /llm/job webhook URL targets RFC1918 / metadata host (webhook SSRF)

`UC_43_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method from datamodel=Web where (Web.uri_path="*/crawl/job*" OR Web.uri_path="*/llm/job*") (Web.url="*webhook*169.254.169.254*" OR Web.url="*webhook*127.0.0.1*" OR Web.url="*webhook*localhost*" OR Web.url="*webhook*metadata.google.internal*" OR Web.url="*webhook*10.*" OR Web.url="*webhook*192.168.*" OR Web.url="*webhook*172.16.*" OR Web.url="*::ffff:*") by host Web.src Web.uri_path | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteUrl has_any ("/crawl/job", "/llm/job")
| where RemoteUrl has_any ("169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost", "::ffff:", "://10.", "://192.168.", "://172.16.", "://172.17.", "://172.18.", "://172.19.", "://172.2", "://172.3")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili

`UC_43_0` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
