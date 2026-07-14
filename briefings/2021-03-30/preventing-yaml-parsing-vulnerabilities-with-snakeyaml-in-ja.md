# [HIGH] Preventing YAML parsing vulnerabilities with snakeyaml in Java

**Source:** Snyk
**Published:** 2021-03-30
**Article:** https://snyk.io/blog/java-yaml-parser-with-snakeyaml/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
March 30, 2021
0 mins read What is YAML? YAML is a human-readable language to serialize data that’s commonly used for config files. The word YAML is an acronym for “YAML ain’t a markup language” and was first released in 2001. You can compare YAML to JSON or XML as all of them are text-based structured formats.
How are YAML, JSON, and XML different? While similar to those languages, YAML is designed to be more readable than JSON and less verbos…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1499.003** — Endpoint Denial of Service: Application Exhaustion Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable snakeyaml < 1.26 exposed to billion-laughs YAML bomb (CVE-2017-18640)

`UC_3169_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2017-18640" OR Vulnerabilities.signature="*snakeyaml*" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | search cve="CVE-2017-18640" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where SoftwareName has "snakeyaml"
| where CveId =~ "CVE-2017-18640"
| project Timestamp, DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| sort by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
