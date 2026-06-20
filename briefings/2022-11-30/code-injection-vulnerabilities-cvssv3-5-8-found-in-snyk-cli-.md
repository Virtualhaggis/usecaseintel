# [HIGH] Code injection vulnerabilities (CVSSv3 5.8) found in Snyk CLI and IDE plugins

**Source:** Snyk
**Published:** 2022-11-30
**Article:** https://snyk.io/blog/code-injection-vulns-cli-ide-plugins-medium-sev/

## Threat Profile

Snyk Blog In this article
Written by Carm Janneteau 
November 30, 2022
0 mins read As a Snyk user, we want to let you know about two new medium severity (CVSSv3 5.8) vulnerabilities in our CLI and IDE plugins.
CVE-2022-24441 
CVE-2022-22984 
Although hard to exploit, these vulnerabilities can lead to arbitrary code execution on the host system. See below for details on how to mitigate these risks and stay safe.
CVE-2022-24441 – Code injection in Snyk CLI and Snyk IDE plugins The Snyk CLI may all…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-24441`
- **CVE:** `CVE-2022-22984`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-24441`, `CVE-2022-22984`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
