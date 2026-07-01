# [MED] Java JSON deserialization problems with the Jackson ObjectMapper

**Source:** Snyk
**Published:** 2021-12-01
**Article:** https://snyk.io/blog/java-json-deserialization-problems-jackson-objectmapper/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
December 1, 2021
0 mins read In a previous blog post, we took a look at Java’s custom serialization platform and what the security implications are. And more recently, I wrote about how improvements in Java 17 can help you prevent insecure deserialization. However, nowadays, people aren’t as dependent on Java’s custom serialization, opting instead to use JSON. JSON is the most widespread format for data serialization, it is human readable and n…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-12384`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-12384`


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
