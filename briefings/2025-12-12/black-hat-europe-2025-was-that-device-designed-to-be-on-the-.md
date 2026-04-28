# [MED] Black Hat Europe 2025: Was that device designed to be on the internet at all?

**Source:** ESET WeLiveSecurity
**Published:** 2025-12-12
**Article:** https://www.welivesecurity.com/en/internet-of-things/black-hat-europe-2025-device-designed-internet/

## Threat Profile

“ A City of a Thousand Zero Days ” is the partial title of a talk at Black Hat Europe 2025. I am sure you will appreciate why these few words sparked my interest enough to dedicate time to the presentation; especially given that back in 2019 I delivered a talk on the evolving risk of smart buildings at Segurinfo in Argentina.
The talk at Black Hat, delivered by Gjoko Krstic of Zero Science Lab, focused on one vendor of building management systems and how the evolution of one of their products th…

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
