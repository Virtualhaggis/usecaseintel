# [HIGH] New 'HTTP/2 Bomb' DoS attack crashes web servers in under a minute

**Source:** BleepingComputer
**Published:** 2026-06-03
**Article:** https://www.bleepingcomputer.com/news/security/new-http-2-bomb-dos-attack-crashes-web-servers-in-under-a-minute/

## Threat Profile

New 'HTTP/2 Bomb' DoS attack crashes web servers in under a minute 
By Bill Toulas 
June 3, 2026
03:08 PM
0 
A new denial-of-service (DoS) attack dubbed HTTP/2 Bomb can be launched from a single machine to take down web servers within seconds.
The technique works on default HTTP/2 configurations of major web servers, including NGINX, Apache HTTP Server, Microsoft IIS, Envoy, and Cloudflare Pingora.
Discovered by OpenAI's Codex software agent under the guidance of researchers at offensive securit…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-49975`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1499.003** — Application Exhaustion Flood
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1499.002** — Service Exhaustion Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable HTTP/2 server inventory (CVE-2026-49975 — nginx/mod_http2/Envoy/IIS)

`UC_17_1` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Vulnerabilities.signature) as signature, values(Vulnerabilities.severity) as severity, max(_time) as last_seen from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2026-49975" OR Vulnerabilities.signature="*HTTP/2 Bomb*" OR Vulnerabilities.signature="*nginx 1.29.7*" OR Vulnerabilities.signature="*mod_http2*" OR Vulnerabilities.signature="*Envoy 1.37.2*") by Vulnerabilities.dest Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | convert ctime(last_seen) | sort - last_seen
```

**Defender KQL:**
```kql
// HTTP/2 Bomb (CVE-2026-49975) — vulnerable HTTP/2 server inventory
let TvmHits =
    DeviceTvmSoftwareVulnerabilities
    | where Timestamp > ago(7d)
    | where CveId == "CVE-2026-49975"
    | project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, Source="TVM CVE feed";
let InventoryHits =
    DeviceTvmSoftwareInventory
    | where Timestamp > ago(7d)
    // article names these specific vulnerable builds
    | where (SoftwareName has "nginx"  and SoftwareVersion == "1.29.7")
         or (SoftwareName has "httpd"  and SoftwareVersion startswith "2.4." and SoftwareVersion !in ("2.4.68","2.4.69","2.4.70"))
         or (SoftwareName has "mod_http2" and SoftwareVersion startswith "2.0." and SoftwareVersion < "2.0.41")
         or (SoftwareName has "envoy" and SoftwareVersion == "1.37.2")
         or (SoftwareName has "IIS"   and OSVersion has "Windows Server 2025")
    | extend CveId="CVE-2026-49975", Source="Inventory match"
    | project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, Source;
union TvmHits, InventoryHits
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId, DeviceName) on DeviceName
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareName, SoftwareVersion, IsInternetFacing, PublicIP, CveId, Source
| order by IsInternetFacing desc, Timestamp desc
```

### [LLM] HTTP/2 Bomb stall signature — long-hung HTTP/2 requests with near-zero response bytes

`UC_17_2` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, sum(Web.bytes_in) as bytes_in_total, sum(Web.bytes_out) as bytes_out_total, max(Web.duration) as max_duration, dc(Web.url) as distinct_urls from datamodel=Web.Web where Web.duration>=20 Web.bytes_out<1024 Web.dest_port IN (443,8443,80) by Web.src Web.dest Web.site _time span=1m | `drop_dm_object_name(Web)` | where count>=3 AND bytes_out_total<5120 | sort - max_duration
```

**Defender KQL:**
```kql
// HTTP/2 Bomb stall signature — multiple held inbound HTTP/2 connections from a single source
let WebProcs = dynamic(["nginx.exe","httpd.exe","w3wp.exe","envoy.exe","iisexpress.exe","apache2","nginx","httpd"]);
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType =~ "InboundConnectionAccepted"
| where LocalPort in (443, 8443, 80)
| where InitiatingProcessFileName has_any (WebProcs)
| where RemoteIPType == "Public"        // ignore intra-DC health checks
| summarize ConnCount       = count(),
            DistinctRemotePorts = dcount(RemotePort),
            FirstConn        = min(Timestamp),
            LastConn         = max(Timestamp),
            HoldSeconds      = datetime_diff('second', max(Timestamp), min(Timestamp))
        by DeviceName, RemoteIP, InitiatingProcessFileName, bin(Timestamp, 1m)
| where ConnCount >= 20 and HoldSeconds >= 20    // 20+ simultaneous inbound h2 conns held ≥20s — matches Apache/Envoy 32GB-in-20s profile
| project FirstConn, LastConn, DeviceName, RemoteIP, InitiatingProcessFileName, ConnCount, DistinctRemotePorts, HoldSeconds
| order by ConnCount desc
```

### [LLM] Web-tier worker crash / OOM storm following HTTP/2 Bomb memory exhaustion

`UC_17_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as spawn_count, dc(Processes.process_id) as distinct_pids, min(_time) as first_spawn, max(_time) as last_spawn from datamodel=Endpoint.Processes where (Processes.process_name IN ("nginx.exe","httpd.exe","apache2","w3wp.exe","envoy.exe","nginx","httpd")) by Processes.dest Processes.process_name _time span=5m | `drop_dm_object_name(Processes)` | where spawn_count >= 10 | eval crash_storm_window=(last_spawn-first_spawn) | sort - spawn_count
```

**Defender KQL:**
```kql
// HTTP/2 Bomb impact — web worker restart storm (process pool churn from OOM)
let WebProcs = dynamic(["nginx.exe","httpd.exe","apache2","httpd","w3wp.exe","envoy.exe","nginx"]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ WebProcs or FileName has_any (WebProcs)
| where AccountName !endswith "$"
| summarize SpawnCount    = count(),
            DistinctPids  = dcount(ProcessId),
            FirstSpawn    = min(Timestamp),
            LastSpawn     = max(Timestamp),
            SampleParent  = any(InitiatingProcessFileName),
            SampleCmd     = any(ProcessCommandLine)
        by DeviceName, FileName, bin(Timestamp, 5m)
| where SpawnCount >= 10                           // 10 worker (re)starts in 5 min — well above normal recycle rate
| extend StormWindowSec = datetime_diff('second', LastSpawn, FirstSpawn)
| project FirstSpawn, LastSpawn, StormWindowSec, DeviceName, FileName, SpawnCount, DistinctPids, SampleParent, SampleCmd
| order by SpawnCount desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-49975`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
