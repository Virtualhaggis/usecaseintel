# [HIGH] SnakeYaml 2.0: Solving the unsafe deserialization vulnerability

**Source:** Snyk
**Published:** 2023-06-21
**Article:** https://snyk.io/blog/snakeyaml-unsafe-deserialization-vulnerability/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
June 21, 2023
0 mins read In the December of last year, we reported CVE-2022-1471 to you. This unsafe deserialization problem could easily lead to arbitrary code execution under the right circumstances. 
In the deep-dive blog post “ Unsafe deserialization vulnerability in SnakeYaml (CVE-2022-1471) ”, I explained the problems in this library and how it could be executed. The gist of the problem was that by default SnakeYaml parsed the incoming y…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-1471`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-1471`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
