# [CRIT] OpenSSL HollowByte Flaw Could Freeze Server Memory with 11-Byte TLS Requests

**Source:** The Hacker News
**Published:** 2026-07-17
**Article:** https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html

## Threat Profile

OpenSSL HollowByte Flaw Could Freeze Server Memory with 11-Byte TLS Requests 
 Swati Khandelwal  Jul 17, 2026 Vulnerability / Server Security 
Eleven bytes will make an unpatched OpenSSL server set aside up to 131 KB of memory for a message that never arrives. On the glibc systems Okta tested, that memory is gone until the process restarts.
OpenSSL shipped the HollowByte fix in June with no CVE, no advisory, and no changelog entry pointing at it. Okta's Red Team, which reported the denial-of-s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-34183`
- **CVE:** `CVE-2025-66199`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1499** — Endpoint Denial of Service
- **T1499.003** — Application Exhaustion Flood
- **T1499.004** — Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenSSL build missing June 9 HollowByte fix (below 4.0.1/3.6.3/3.5.7/3.4.6/3.0.21)

`UC_98_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.signature="*OpenSSL*" OR Vulnerabilities.cve IN ("CVE-2026-34183","CVE-2025-66199")) by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.cve, Vulnerabilities.severity
| `drop_dm_object_name(Vulnerabilities)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where Timestamp > ago(1d)
| where SoftwareName has "openssl"
| extend Ver = parse_version(SoftwareVersion)
| where (SoftwareVersion startswith "4.0." and Ver < parse_version("4.0.1"))
     or (SoftwareVersion startswith "3.6." and Ver < parse_version("3.6.3"))
     or (SoftwareVersion startswith "3.5." and Ver < parse_version("3.5.7"))
     or (SoftwareVersion startswith "3.4." and Ver < parse_version("3.4.6"))
     or (SoftwareVersion startswith "3.0." and Ver < parse_version("3.0.21"))
     or (SoftwareVersion startswith "3.1.") or (SoftwareVersion startswith "3.2.") or (SoftwareVersion startswith "3.3.")
     or (SoftwareVersion startswith "1.")   // 1.1.1 / 1.0.2 extended-support branches — HollowByte fix status unconfirmed, treat as vulnerable
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion
| sort by DeviceName asc
```

### OOM-killer terminates TLS-terminating daemon (HollowByte memory exhaustion impact)

`UC_98_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=syslog OR sourcetype=linux_messages_syslog OR sourcetype="linux:messages") ("Out of memory: Killed process" OR "invoked oom-killer" OR "oom_reaper") (nginx OR httpd OR apache2 OR haproxy OR stunnel OR envoy OR openssl)
| stats count min(_time) as firstTime max(_time) as lastTime values(_raw) as sampleMessages by host
| sort - count
```

### Crash-loop / rapid restart of TLS server process (post-exhaustion instability)

`UC_98_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("nginx","httpd","apache2","haproxy","stunnel") by Processes.dest, Processes.process_name, _time span=10m
| `drop_dm_object_name(Processes)`
| where count > 20
| sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(6h)
| where FileName in~ ("nginx", "httpd", "apache2", "haproxy", "stunnel")
| summarize SpawnCount = count(), SampleCmd = any(ProcessCommandLine), Parents = make_set(InitiatingProcessFileName, 5), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, DeviceId, FileName, bin(Timestamp, 10m)
| where SpawnCount > 20   // healthy TLS daemons spawn a fixed worker pool once; >20 respawns/10min = crash-loop
| sort by SpawnCount desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-34183`, `CVE-2025-66199`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
