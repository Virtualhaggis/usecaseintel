# [MED] Foxit, LibRaw vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-04-16
**Article:** https://blog.talosintelligence.com/foxit-libraw-vulnerabilities/

## Threat Profile

Foxit, LibRaw vulnerabilities 
By 
Kri Dontje 
Thursday, April 16, 2026 15:00
Vulnerability Roundup
Cisco Talos’ Vulnerability Discovery & Research team recently disclosed one Foxit Reader vulnerability, and six LibRaw file reader vulnerabilities.
The vulnerabilities mentioned in this blog post have been patched by their respective vendors, all in adherence to Cisco’s third-party vulnerability disclosure policy .    
For Snort coverage that can detect the exploitation of these vulnerabilities, d…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-3779`
- **CVE:** `CVE-2026-20911`
- **CVE:** `CVE-2026-21413`
- **CVE:** `CVE-2026-20889`
- **CVE:** `CVE-2026-24660`
- **CVE:** `CVE-2026-24450`
- **CVE:** `CVE-2026-20884`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Asset exposure — vulnerability matches article CVE(s)

`_uc` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN ("CVE-2026-3779", "CVE-2026-20911", "CVE-2026-21413", "CVE-2026-20889", "CVE-2026-24660", "CVE-2026-24450", "CVE-2026-20884")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2026-3779", "CVE-2026-20911", "CVE-2026-21413", "CVE-2026-20889", "CVE-2026-24660", "CVE-2026-24450", "CVE-2026-20884")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
