# [HIGH] New language-specific Snyk Top 10 for open source vulnerabilities

**Source:** Snyk
**Published:** 2023-03-15
**Article:** https://snyk.io/blog/language-specific-snyk-top-10-open-source-2022/

## Threat Profile

Snyk Blog In this article
Written by Erin Cullen 
March 15, 2023
0 mins read Developers use open source code because it facilitates fast development. In fact, the vast majority of code in modern applications is open source. But just like any other code, open source libraries are open to vulnerabilities that can negatively affect a wide range of end-user products. So with widespread usage of open source, it's important for teams to be aware of the risks that can be hidden in the libraries they us…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-43138`
- **CVE:** `CVE-2021-3807`
- **CVE:** `CVE-2022-2421`
- **CVE:** `CVE-2022-25319`
- **CVE:** `CVE-2022-3518`
- **CVE:** `CVE-2022-2144`
- **CVE:** `CVE-2022-24858`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-43138`, `CVE-2021-3807`, `CVE-2022-2421`, `CVE-2022-25319`, `CVE-2022-3518`, `CVE-2022-2144`, `CVE-2022-24858`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
