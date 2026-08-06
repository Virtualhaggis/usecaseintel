# [HIGH] CRLF injection found in popular Python dependency, urllib3

**Source:** Snyk
**Published:** 2019-05-15
**Article:** https://snyk.io/blog/crlf-injection-found-in-popular-python-dependency/

## Threat Profile

Snyk Blog Written by Hayley Denbraver 
May 15, 2019
0 mins read On April 18, 2019 a CRLF injection vulnerability was found in the popular Python library, urllib3 . The urllib3 library is an HTTP client for Python that includes valuable features such as thread safety, connection pooling, client-side SSL/TLS verification, and more. It is used widely in the Python ecosystem, including within requests, another popular library. In fact, urllib3 is used by more than 500 open source libraries . If you …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable urllib3 (<= 1.24.2 / CVE-2019-11236) present in software inventory

`UC_3535_0` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2019-11236"
| where SoftwareName has "urllib3"
| summarize arg_max(Timestamp, *) by DeviceId, SoftwareVersion
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| sort by DeviceName asc
```

### CRLF / HTTP-header injection in URL query string (urllib3 CVE-2019-11236 PoC shape)

`UC_3535_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.uri_query="*%0d%0a*" OR Web.uri_query="*%0D%0A*" OR Web.uri_query="*X-injected*" OR Web.uri_query="*%20HTTP/1.1*") by Web.src Web.dest Web.site Web.http_method Web.uri_path Web.uri_query Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
