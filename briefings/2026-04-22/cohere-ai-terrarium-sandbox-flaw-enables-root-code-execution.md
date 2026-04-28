# [MED] Cohere AI Terrarium Sandbox Flaw Enables Root Code Execution, Container Escape

**Source:** The Hacker News
**Published:** 2026-04-22
**Article:** https://thehackernews.com/2026/04/cohere-ai-terrarium-sandbox-flaw.html

## Threat Profile

A critical security vulnerability has been disclosed in a Python-based sandbox called Terrarium that could result in arbitrary code execution. The vulnerability, tracked as CVE-2026-5752, is rated 9.3 on the CVSS scoring system. "Sandbox escape vulnerability in Terrarium allows arbitrary code execution with root privileges on a host process via JavaScript prototype chain traversal," according to

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-5752`

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
    where Vulnerabilities.signature IN ("CVE-2026-5752")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2026-5752")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
