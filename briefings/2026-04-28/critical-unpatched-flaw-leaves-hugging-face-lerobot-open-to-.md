# [HIGH] Critical Unpatched Flaw Leaves Hugging Face LeRobot Open to Unauthenticated RCE

**Source:** The Hacker News
**Published:** 2026-04-28
**Article:** https://thehackernews.com/2026/04/critical-cve-2026-25874-leaves-hugging.html

## Threat Profile

Cybersecurity researchers have disclosed details of a critical security flaw impacting LeRobot, Hugging Face's open-source robotics platform with nearly 24,000 GitHub stars, that could be exploited to achieve remote code execution. The vulnerability in question is CVE-2026-25874 (CVSS score: 9.3), which has been described as a case of untrusted data deserialization stemming from the use of the

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-25874`

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
    where Vulnerabilities.signature IN ("CVE-2026-25874")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2026-25874")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
