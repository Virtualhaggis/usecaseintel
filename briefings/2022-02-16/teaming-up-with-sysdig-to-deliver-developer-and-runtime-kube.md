# [HIGH] Teaming up with Sysdig to deliver developer and runtime Kubernetes security

**Source:** Snyk
**Published:** 2022-02-16
**Article:** https://snyk.io/blog/snyk-teaming-up-with-sysdig/

## Threat Profile

Snyk Blog In this article
Written by Jim Armstrong 
February 16, 2022
0 mins read Today, we’re excited to announce a partnership with Sysdig to provide container and Kubernetes security together — from code to cluster. Together, Snyk and Sysdig can help developers secure code and containers in development, protect the runtime Kubernetes environment, and deliver feedback and visibility from production back to developers, eliminating the noise of container vulnerabilities. Containers have been a f…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
