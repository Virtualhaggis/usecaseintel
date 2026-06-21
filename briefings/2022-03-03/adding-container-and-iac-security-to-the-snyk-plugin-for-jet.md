# [MED] Adding Container and IaC security to the Snyk plugin for Jetbrains

**Source:** Snyk
**Published:** 2022-03-03
**Article:** https://snyk.io/blog/snyk-jetbrains-plugin-iac-container/

## Threat Profile

Snyk Blog In this article
Written by Georgi Mitev 
March 3, 2022
0 mins read We’re excited to announce that infrastructure as code (IaC) and container security are joining code and open source dependency security in the free Snyk plugin for JetBrains IDEs.
As of today, developers using JetBrains IDEs can secure their entire application with a click of a button. Snyk Security for JetBrains increases code security and reduces time spent on manual code reviews by empowering developers to find and f…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `registry.terraform.io`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `registry.terraform.io`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
