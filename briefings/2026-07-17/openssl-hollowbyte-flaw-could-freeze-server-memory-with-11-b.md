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
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation
- **T1499.002** — Endpoint Denial of Service: Service Exhaustion Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unpatched OpenSSL exposed to HollowByte DoS (pre-2026-06-09 build, no CVE to scan)

`UC_32_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-34183" by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
// Direct build-version hunt — catches HollowByte-vulnerable OpenSSL even where the CVE-2026-34183 proxy is patched but the un-numbered fix was not backported.
DeviceTvmSoftwareInventory
| where SoftwareVendor has "openssl" or SoftwareName has "openssl"
| extend Parts = split(SoftwareVersion, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Patch = toint(Parts[2])
| where (Major == 3 and Minor == 0 and Patch < 21)   // 3.0.x fixed at 3.0.21
     or (Major == 3 and Minor == 4 and Patch < 6)    // 3.4.x fixed at 3.4.6
     or (Major == 3 and Minor == 5 and Patch < 7)    // 3.5.x fixed at 3.5.7
     or (Major == 3 and Minor == 6 and Patch < 3)    // 3.6.x fixed at 3.6.3
     or (Major == 4 and Minor == 0 and Patch < 1)    // 4.0.x fixed at 4.0.1
     or (Major == 3 and Minor in (1, 2, 3))          // EOL 3.x branches, no HollowByte fix shipped
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, OSPlatform, EndOfSupportStatus
| sort by SoftwareVersion asc
```

### OpenSSL TLS server OOM-kill / memory pressure (HollowByte glibc heap fragmentation)

`UC_32_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=syslog OR sourcetype=linux_messages_syslog OR source="/var/log/messages" OR source="/var/log/syslog") ("Out of memory: Killed process" OR "oom-kill:" OR "oom_reaper") (nginx OR openssl OR httpd OR apache2 OR haproxy OR stunnel OR "nginx: worker")
| stats count min(_time) as firstTime max(_time) as lastTime values(_raw) as sampleMessage by host
| where count >= 2
| sort - count
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-34183`, `CVE-2025-66199`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
