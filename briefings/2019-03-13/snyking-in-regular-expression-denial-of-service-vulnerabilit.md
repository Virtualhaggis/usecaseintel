# [HIGH] Snyking in - regular expression denial of service vulnerability exploit in the ms package

**Source:** Snyk
**Published:** 2019-03-13
**Article:** https://snyk.io/blog/snyking-in-regular-expression-denial-of-service-vulnerability-exploit-in-the-ms-package/

## Threat Profile

Snyk Blog In this article
Written by Simon Maple 
March 13, 2019
0 mins read Welcome to another edition of our Snyking In exploit series! Last time we looked at a directory traversal vulnerability exploit in the st library . In this episode, we’ll be looking at the regular expression denial of service vulnerability, demonstrating how it can be exploited, as well as the potential risk they pose to your data and systems. 
We will also show you how to both find and fix this type of vulnerability in…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ReDoS in ms time-parser: oversized web request body with multi-second server processing time

`UC_3531_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as request_count min(_time) as firstTime max(_time) as lastTime values(Web.status) as status from datamodel=Web where Web.http_method=POST Web.bytes_in>10000 by Web.src Web.dest Web.site Web.uri_path Web.http_method Web.bytes_in 
| `drop_dm_object_name(Web)` 
| eval note="oversized POST body (>10000 bytes) to a duration-parsing endpoint - candidate ms ReDoS (CVE-2017-20162); correlate with raw web logs for multi-second response_time" 
| convert ctime(firstTime) ctime(lastTime) 
| sort - bytes_in
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
