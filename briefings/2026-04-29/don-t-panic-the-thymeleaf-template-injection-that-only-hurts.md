# [HIGH] Don't Panic: The Thymeleaf Template Injection That Only Hurts If You Let It (CVE-2026-40478)

**Source:** Snyk
**Published:** 2026-04-29
**Article:** https://snyk.io/blog/thymeleaf-injection/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
April 29, 2026
0 mins read The Thymeleaf vulnerability with a CVSS score of 9.1 grabs your attention, as it should. But before you call the cavalry and claim this as the new Log4shell, read this first.
CVE-2026-40478 is a server-side template injection vulnerability in Thymeleaf discovered by pentester Dawid Bakaj . Thymeleaf is a templating engine in Java that is used for server-side webpage rendering. The sandbox that normally prevents arbitr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-40478`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-40478`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
