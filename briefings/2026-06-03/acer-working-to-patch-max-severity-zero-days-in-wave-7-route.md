# [HIGH] Acer working to patch max severity zero-days in Wave 7 routers

**Source:** BleepingComputer
**Published:** 2026-06-03
**Article:** https://www.bleepingcomputer.com/news/security/acer-warns-of-max-severity-zero-days-affecting-wave-7-routers/

## Threat Profile

Acer working to patch max severity zero-days in Wave 7 routers 
By Sergiu Gatlan 
June 3, 2026
07:35 AM
0 
Acer confirmed that it's working to address two maximum-severity zero-day vulnerabilities affecting its Wave 7 mesh routers.
According to a Friday security advisory , the two security flaws were reported by security researcher Gergo Pap and affect Wave 7 routers running firmware version T7c_GBL_1.01.000055 or earlier.
The first zero-day, a broken access control vulnerability tracked as CVE-…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-49200`
- **CVE:** `CVE-2026-49201`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1601.002** — Modify System Image: Patch System Image
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Acer Wave 7 unauthenticated acer_cgi.log credential disclosure (CVE-2026-49200)

`UC_13_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as methods values(Web.status) as statuses values(Web.http_user_agent) as user_agents from datamodel=Web where Web.url="*acer_cgi.log*" by Web.src, Web.dest, Web.dest_port, Web.url | `drop_dm_object_name(Web)` | where statuses="200" OR isnull(statuses) | eval is_admin_destination=if(match(dest,"^192\.168\.76\.1$") OR like(dest,"%acerconnect.com"),1,0) | sort 0 -lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "acer_cgi.log"
   or (RemoteUrl has_any ("acerconnect.com", "192.168.76.1") and AdditionalFields has "acer_cgi.log")
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain
| order by Timestamp desc
```

### [LLM] Acer Wave 7 upload.cgi backup tamper for persistent backdoor (CVE-2026-49201)

`UC_13_2` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime sum(Web.bytes_in) as total_bytes_in values(Web.status) as statuses values(Web.http_user_agent) as user_agents from datamodel=Web where Web.url="*upload.cgi*" Web.http_method=POST by Web.src, Web.dest, Web.dest_port, Web.url | `drop_dm_object_name(Web)` | eval is_acer_admin=if(match(dest,"^192\.168\.76\.1$") OR like(dest,"%acerconnect.com"),1,0) | where is_acer_admin=1 OR total_bytes_in > 1024 | sort 0 -lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "upload.cgi"
   or (RemoteUrl has_any ("acerconnect.com", "192.168.76.1") and AdditionalFields has "upload.cgi")
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemoteUrl, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-49200`, `CVE-2026-49201`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
