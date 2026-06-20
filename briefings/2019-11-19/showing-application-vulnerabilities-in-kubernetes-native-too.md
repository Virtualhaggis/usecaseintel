# [HIGH] Showing application vulnerabilities in Kubernetes-native tooling

**Source:** Snyk
**Published:** 2019-11-19
**Article:** https://snyk.io/blog/showing-application-vulnerabilities-in-kubernetes-native-tooling/

## Threat Profile

Snyk Blog In this article
Written by Gareth Rushgrove 
November 19, 2019
0 mins read Building on the new Kubernetes features in Snyk Container , we’ve been experimenting with integrating vulnerability data more closely into the Kubernetes ecosystem. Snyk has an extensive set of dashboards and reporting features, which are great if you’re focused just on security. But what about if you don’t want to switch context from what you’re doing with Kubernetes? Can we use the rich set of APIs in Snyk Con…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2016-2781`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2016-2781`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
