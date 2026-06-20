# [HIGH] Uncharted territory - discovering vulnerabilities in public Helm Charts

**Source:** Snyk
**Published:** 2019-11-18
**Article:** https://snyk.io/blog/uncharted-territory-discovering-vulnerabilities-in-public-helm-charts/

## Threat Profile

Snyk Blog In this article
Written by Gareth Rushgrove 
November 18, 2019
0 mins read Similar to our report on Docker image security , we wanted to take a look at the state of vulnerabilities in the public Helm Charts repository .
Helm is a popular package manager for Kubernetes. As well as being used by developers to package their own applications, the official Charts repository contains 100s of Charts you can use to install third party software like Jenkins, PostgreSQL and lots more. This saves…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2005-2541`
- **CVE:** `CVE-2019-9619`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2005-2541`, `CVE-2019-9619`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
