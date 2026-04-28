# [LOW] [Video] The TTP Ep. 22: The Collapse of the Patch Window

**Source:** Cisco Talos
**Published:** 2026-04-10
**Article:** https://blog.talosintelligence.com/video-the-ttp-ep-22-the-collapse-of-the-patch-window/

## Threat Profile

[Video] The TTP Ep. 22: The Collapse of the Patch Window 
By 
Hazel Burton 
Friday, April 10, 2026 11:29
2025YiR
Year In Review
One of the clearest trends in the 2025 Talos Year in Review is just how quickly vulnerabilities are now being turned into working exploits. What used to take weeks or months is now happening in days, sometimes hours — and in some cases, exploitation is beginning almost immediately after vulnerability details are made public.
The process of exploitation itself is changin…

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
