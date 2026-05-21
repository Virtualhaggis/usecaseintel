# [HIGH] Snyk Helps Secure the Golang Bento Project

**Source:** Snyk
**Published:** 2025-03-12
**Article:** https://snyk.io/blog/snyk-helps-secure-the-golang-bento-project/

## Threat Profile

Snyk Blog In this article
Written by Phill Garrett 
March 12, 2025
0 mins read Snyk is exploring using the open-source Golang project Bento to read data from Kafka streams and materialize intelligence to various outputs. We are pleased to share that we are proactively helping secure the Bento project by contributing dependency fix updates.  
What is Bento? Bento is an open-source streaming data processing tool designed for ease of use and reliability. It features declarative configuration, enabl…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-22869`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-22869`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
