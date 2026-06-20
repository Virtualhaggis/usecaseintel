# [HIGH] Why you should upgrade to Maven version 3.8.1

**Source:** Snyk
**Published:** 2021-07-19
**Article:** https://snyk.io/blog/why-you-should-upgrade-to-maven-version-3-8-1/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
July 19, 2021
0 mins read If you are working in the Java ecosystem and building your applications with an older Maven version, this message is for you.
Check your Maven version by typing mvn -version ! If you are still running on an old Maven version like 3.6.3 or below you definitely need to upgrade to version 3.8.1 because of security reasons. Be aware that to run Maven 3.8.1, Java 7+ is required.
Luckily we found out in the JVM Ecosystem rep…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-26291`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-26291`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
