# [HIGH] Under the C: A glance at C/C++ vulnerabilities in Python land

**Source:** Snyk
**Published:** 2022-04-28
**Article:** https://snyk.io/blog/under-the-c-vulnerabilities-in-python/

## Threat Profile

Snyk Blog In this article
Written by Aviad Hahami 
April 28, 2022
0 mins read While most developers — myself included —  primarily write in higher-level languages like Python or JavaScript, sometimes you need to add in native elements to improve performance or other project aspects. Since these native extension invocations are typically written in C or C++, suddenly a project primarily using JavaScript or Python must also account for potential C/C++ transient dependencies.
In May 2021, Snyk acqu…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2003-1564`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2003-1564`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
