# [MED] Apple Fixes iOS Flaw That Let FBI Recover Deleted Signal Messages

**Source:** The Hacker News
**Published:** 2026-04-23
**Article:** https://thehackernews.com/2026/04/apple-patches-ios-flaw-that-stored.html

## Threat Profile

Apple has rolled out a software fix for iOS and iPadOS to address a Notification Services flaw that stored notifications marked for deletion on the device. The vulnerability, tracked as CVE-2026-28950 (CVSS score: N/A), has been described as a logging issue that has been addressed with improved data redaction. "Notifications marked for deletion could be unexpectedly retained on the device,"

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-28950`

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
    where Vulnerabilities.signature IN ("CVE-2026-28950")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2026-28950")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
