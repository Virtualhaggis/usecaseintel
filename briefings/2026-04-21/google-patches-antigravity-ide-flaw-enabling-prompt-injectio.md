# [LOW] Google Patches Antigravity IDE Flaw Enabling Prompt Injection Code Execution

**Source:** The Hacker News
**Published:** 2026-04-21
**Article:** https://thehackernews.com/2026/04/google-patches-antigravity-ide-flaw.html

## Threat Profile

Cybersecurity researchers have discovered a vulnerability in Google's agentic integrated development environment (IDE), Antigravity, that could be exploited to achieve code execution. The flaw, since patched, combines Antigravity's permitted file-creation capabilities with an insufficient input sanitization in Antigravity's native file-searching tool, find_by_name, to bypass the program's Strict

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

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
    where Vulnerabilities.signature IN ("-")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("-")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
```


## Why this matters

Severity classified as **LOW** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
