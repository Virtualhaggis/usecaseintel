# [LOW] Hackers Use Fake Purchase Orders to Deploy JS.MonoGlyphRAT Targeting US Enterprises

**Source:** Cyber Security News
**Published:** 2026-06-03
**Article:** https://cybersecuritynews.com/hackers-use-fake-purchase-orders-to-deploy-js-monoglyphrat/

## Threat Profile

A stealthy new threat is quietly making its way through US businesses, and most traditional security tools are completely missing it. Researchers have uncovered a previously unknown piece of malware that disguises itself as an everyday business document — a purchase order, a quote, or a request for proposal. Once an unsuspecting employee opens the [&#8230;] The post Hackers Use Fake Purchase Orders to Deploy JS.MonoGlyphRAT Targeting US Enterprises appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `158.94.211.76`
- **IPv4 (defanged):** `91.92.243.79`
- **Domain (defanged):** `aryamint.com`
- **Domain (defanged):** `scan.aryamint.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `158.94.211.76`, `91.92.243.79`, `aryamint.com`, `scan.aryamint.com`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
