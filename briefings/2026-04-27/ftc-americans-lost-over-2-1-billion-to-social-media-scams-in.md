# [MED] FTC: Americans lost over $2.1 billion to social media scams in 2025

**Source:** BleepingComputer
**Published:** 2026-04-27
**Article:** https://www.bleepingcomputer.com/news/security/ftc-americans-lost-over-21-billion-to-social-media-scams-in-2025/

## Threat Profile

FTC: Americans lost over $2.1 billion to social media scams in 2025 
By Sergiu Gatlan 
April 27, 2026
12:27 PM
0 
The U.S. Federal Trade Commission (FTC) warned of a massive increase in losses from social media scams since 2020, exceeding $2.1 billion in 2025.
According to reports to the FTC's Consumer Sentinel Network, all age groups (except those 80 and over, who were mainly targeted via phone calls) lost more money to scams originating on Facebook than to any other social media platform.
Repo…

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

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
