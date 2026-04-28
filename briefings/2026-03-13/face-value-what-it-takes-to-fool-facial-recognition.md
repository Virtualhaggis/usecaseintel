# [HIGH] Face value: What it takes to fool facial recognition

**Source:** ESET WeLiveSecurity
**Published:** 2026-03-13
**Article:** https://www.welivesecurity.com/en/privacy/face-value-what-takes-fool-facial-recognition/

## Threat Profile

Facial recognition is increasingly embedded in everything from airport boarding gates to bank onboarding flows. The widely-held assumption is that a face is hard to fake and that matching a live face to a trusted source is a reliable identity signal.
Jake Moore , ESET Global Cybersecurity Advisor, recently put this assumption through several practical stress tests. His experiments showed that the powerful technology can actually be both misused and defeated.
In one test, Jake used a pair of modi…

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

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
