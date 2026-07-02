# [CRIT] Update: OpenSSL high severity vulnerabilities

**Source:** Snyk
**Published:** 2022-11-03
**Article:** https://snyk.io/blog/openssl-high-severity-vulnerabilities/

## Threat Profile

Snyk Blog In this article
Written by Vandana Verma Sehgal 
November 3, 2022
0 mins read OpenSSL has released two high severity vulnerabilities — CVE-2022-3602 and CVE-2022-3786 — related to buffer overrun.  OpenSSL initially rated CVE-2022-3602 as critical, but upon further investigation, it was reduced to high severity.
What is Buffer overrun? A buffer overrun/overflow is a specific type of runtime issue that allows a program to write past the end of a buffer or array and corrupt nearby memory …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-3602`
- **CVE:** `CVE-2022-3786`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable OpenSSL 3.0.0–3.0.6 exposure (CVE-2022-3602 / CVE-2022-3786, 'SpookySSL')

`UC_1898_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2022-3602","CVE-2022-3786")) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.category 
| `drop_dm_object_name(Vulnerabilities)` 
| convert ctime(firstTime) ctime(lastTime) 
| sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2022-3602", "CVE-2022-3786")
    or (SoftwareName has "openssl" and SoftwareVersion in ("3.0.0","3.0.1","3.0.2","3.0.3","3.0.4","3.0.5","3.0.6"))
| summarize arg_max(Timestamp, *) by DeviceId, CveId, SoftwareVersion
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-3602`, `CVE-2022-3786`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
