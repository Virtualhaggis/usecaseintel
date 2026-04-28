# [MED] Old habits die hard: 2025’s most common passwords were as predictable as ever

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-20
**Article:** https://www.welivesecurity.com/en/cybersecurity/old-habits-die-hard-2025-most-common-passwords/

## Threat Profile

‘123456’ continues to reign supreme as the most commonly-used password among people across the world, according to two reports, from NordPass and Comparitech , respectively. A full 25 percent of the top 1,000 most-used passwords are made up of nothing but numerals.
In addition, ‘123456’ appealed to people of various age cohorts, as it was the most-favored option among millennials, Generation X and baby boomers alike, and the second most-popular option among Generation Z and the Silent Generation…

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
