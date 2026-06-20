# [HIGH] Ghostcat breach affects all Tomcat versions

**Source:** Snyk
**Published:** 2020-02-26
**Article:** https://snyk.io/blog/ghostcat-breach-affects-all-tomcat-versions/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
February 26, 2020
0 mins read Apache Tomcat is an open source implementation of the Java Servlet, JavaServer Pages, Java Expression Language, and Java WebSocket technologies. Tomcat is one of the most popular Java HTTP web server environments and was released in 1998. 
Ghostcat is a high severity vulnerability in Tomcat discovered by the security researchers of Chaitin Tech on January 3rd. On February 20, the China National Vulnerability Databa…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-1938`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-1938`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
