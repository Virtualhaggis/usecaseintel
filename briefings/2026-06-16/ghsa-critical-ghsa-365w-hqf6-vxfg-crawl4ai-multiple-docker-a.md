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
- **T1083** — File and Directory Discovery
- **T1552.005** — Cloud Instance Metadata API
- **T1046** — Network Service Discovery
- **T1078** — Valid Accounts
- **T1059.007** — JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI /screenshot or /pdf path traversal via output_path parameter

`UC_2_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.status) as status from datamodel=Web where Web.uri_path IN ("/screenshot","/pdf","/screenshot/","/pdf/") Web.http_method=POST by Web.src Web.dest Web.uri_path Web.http_user_agent | `drop_dm_object_name(Web)` | search url="*..*" OR url="*%2e%2e*" OR url="*output_path*..*" OR url="*output_path*%2f..*" | where method="POST"
```

**Defender KQL:**
```kql
// Detect the *effect* of the Crawl4AI path-traversal: chromium/playwright/python writing to paths outside /tmp/crawl4ai-outputs/ on the Crawl4AI container host
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome","chromium","headless_shell","python","python3","uvicorn")
| where InitiatingProcessCommandLine has_any ("crawl4ai","uvicorn","fastapi","playwright")
| where ActionType in ("FileCreated","FileModified")
| where not(FolderPath startswith "/tmp/crawl4ai-outputs/")
| where FolderPath startswith "/etc/" or FolderPath startswith "/root/" or FolderPath startswith "/home/" or FolderPath startswith "/var/" or FolderPath startswith "/usr/" or FileName in~ ("authorized_keys",".bashrc",".profile",".bash_profile","crontab")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Crawl4AI container SSRF egress to cloud metadata or RFC1918 ranges

`UC_2_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic where (All_Traffic.dest_ip="169.254.169.254" OR All_Traffic.dest IN ("metadata.google.internal","metadata","instance-data") OR cidrmatch("10.0.0.0/8", All_Traffic.dest_ip) OR cidrmatch("172.16.0.0/12", All_Traffic.dest_ip) OR cidrmatch("192.168.0.0/16", All_Traffic.dest_ip) OR cidrmatch("127.0.0.0/8", All_Traffic.dest_ip) OR cidrmatch("169.254.0.0/16", All_Traffic.dest_ip)) by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process | `drop_dm_object_name(All_Traffic)` | search src IN ("crawl4ai-*","*crawl4ai*") OR process IN ("python","python3","chrome","chromium","headless_shell","uvicorn")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome","chromium","headless_shell","python","python3","uvicorn")
   or InitiatingProcessCommandLine has_any ("crawl4ai","uvicorn server:app","playwright")
| where RemoteIP == "169.254.169.254"
   or RemoteUrl has_any ("169.254.169.254","metadata.google.internal","metadata.azure.com","instance-data")
   or ipv4_is_in_range(RemoteIP, "10.0.0.0/8")
   or ipv4_is_in_range(RemoteIP, "172.16.0.0/12")
   or ipv4_is_in_range(RemoteIP, "192.168.0.0/16")
   or ipv4_is_in_range(RemoteIP, "127.0.0.0/8")
   or ipv4_is_in_range(RemoteIP, "169.254.0.0/16")
| where RemoteIP != "127.0.0.1" or RemotePort !in (5000,8000,8080,11235)  // exclude self-loopback
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, LocalIP, LocalPort
| order by Timestamp desc
```

### Unauthenticated access to Crawl4AI /monitor/* endpoints incl. destructive cleanup

`UC_2_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as method values(Web.status) as status values(Web.http_user_agent) as ua from datamodel=Web where Web.uri_path IN ("/monitor","/monitor/","/monitor/ws","/monitor/actions/cleanup","/monitor/actions") OR Web.uri_path="/monitor/*" by Web.src Web.dest Web.uri_path Web.url | `drop_dm_object_name(Web)` | where status IN ("200","101","204") | eval is_destructive=if(match(uri_path,"/monitor/actions/"),1,0) | search status=200 OR is_destructive=1
```

### Crawl4AI /execute_js endpoint invocation (pre-patch arbitrary JS / SSRF)

`UC_2_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as method values(Web.status) as status values(Web.bytes_in) as bytes_in values(Web.http_user_agent) as ua from datamodel=Web where Web.uri_path IN ("/execute_js","/execute_js/") OR (Web.uri_path IN ("/crawl","/crawl/stream","/md","/llm","/crawl/job","/llm/job","/screenshot","/pdf") AND (Web.url="*%3A%3Affff%3A*" OR Web.url="*::ffff:*" OR Web.url="*169.254.169.254*" OR Web.url="*metadata.google.internal*")) by Web.src Web.dest Web.uri_path Web.url Web.http_method | `drop_dm_object_name(Web)`
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili

`UC_2_0` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
