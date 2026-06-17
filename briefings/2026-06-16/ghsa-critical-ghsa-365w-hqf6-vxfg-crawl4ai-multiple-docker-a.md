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
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1090** — Proxy
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1078** — Valid Accounts
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Crawl4AI SSRF: outbound to cloud metadata or RFC1918 from crawler process

`UC_7_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest="169.254.169.254" OR All_Traffic.dest="100.100.100.200" OR All_Traffic.dest="fd00:ec2::254" OR All_Traffic.dest_category="internal" OR cidrmatch("10.0.0.0/8",All_Traffic.dest) OR cidrmatch("172.16.0.0/12",All_Traffic.dest) OR cidrmatch("192.168.0.0/16",All_Traffic.dest) OR cidrmatch("127.0.0.0/8",All_Traffic.dest) OR cidrmatch("169.254.0.0/16",All_Traffic.dest)) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | search app="*python*" OR app="*uvicorn*" OR app="*gunicorn*" OR process_name="*python*" OR process_name="*uvicorn*" OR process_name="*gunicorn*"
```

**Defender KQL:**
```kql
let MetadataIPs = dynamic(["169.254.169.254","100.100.100.200","fd00:ec2::254"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (MetadataIPs) or RemoteIPType in ("Private","Loopback","LinkLocal")
| where InitiatingProcessFileName has_any ("python","python3","uvicorn","gunicorn","chrome","chromium","headless_shell")
   or InitiatingProcessCommandLine has_any ("crawl4ai","crawl4ai.server","deploy.docker.server","playwright")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl, RemoteIPType
| order by Timestamp desc
```

### Crawl4AI /execute_js endpoint POST — arbitrary JavaScript RCE vector

`UC_7_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method="POST" AND (Web.url="*/execute_js*" OR Web.uri_path="*/execute_js*") by Web.src, Web.dest, Web.dest_port, Web.url, Web.http_user_agent, Web.status | `drop_dm_object_name(Web)` | where dest_port=11235 OR dest_port=80 OR dest_port=443 OR dest_port=8000 OR dest_port=8080
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (11235, 80, 443, 8000, 8080) or LocalPort in (11235, 80, 443, 8000, 8080)
| where RemoteUrl has "/execute_js" or AdditionalFields has "/execute_js"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalIP, LocalPort, RemoteUrl
| order by Timestamp desc
```

### Crawl4AI unauthenticated /monitor/* access (auth-bypass CWE-306)

`UC_7_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*/monitor*" OR Web.uri_path="*/monitor*") by Web.src, Web.dest, Web.dest_port, Web.url, Web.http_method, Web.status, Web.http_user_agent | `drop_dm_object_name(Web)` | where status>=200 AND status<400
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "/monitor" or AdditionalFields has "/monitor"
| where RemotePort in (11235, 80, 443, 8000, 8080)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-365w-hqf6-vxfg: Crawl4AI: Multiple Docker API Vulnerabili

`UC_7_0` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
