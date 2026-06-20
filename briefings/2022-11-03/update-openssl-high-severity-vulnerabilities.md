# [HIGH] Update: OpenSSL high severity vulnerabilities

**Source:** Snyk
**Published:** 2022-11-03
**Article:** https://snyk.io/blog/openssl-high-severity-vulnerabilities/

## Threat Profile

Snyk Blog In this article
Written by Vandana Verma Sehgal 
November 3, 2022
0 mins read OpenSSL has released two high severity vulnerabilities — CVE-2022-3602 and CVE-2022-3786 — related to buffer overrun.  OpenSSL initially rated CVE-2022-3602 as critical, but upon further investigation, it was reduced to high severity.
What is Buffer overrun? A buffer overrun/overflow is a specific type of runtime issue that allows a program to write past the end of a buffer or array and corrupt nearby memory …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-3602`
- **CVE:** `CVE-2022-3786`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-3602`, `CVE-2022-3786`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
