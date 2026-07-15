# [HIGH] Firefox, Chrome, Adobe, and VMware Updates Fix Multiple Critical Security Flaws

**Source:** The Hacker News
**Published:** 2026-07-15
**Article:** https://thehackernews.com/2026/07/firefox-chrome-adobe-and-vmware-updates.html

## Threat Profile

Firefox, Chrome, Adobe, and VMware Updates Fix Multiple Critical Security Flaws 
 Ravie Lakshmanan  Jul 15, 2026 Vulnerability / Browser Security 
Mozilla has released updates to address two critical flaws in Firefox for which it warned that exploit code has been published.
The vulnerabilities are listed below -
CVE-2026-15718 , an invalid pointer in the JavaScript: WebAssembly component
CVE-2026-15719 , a site isolation in the DOM: Navigation component
"We are aware that exploit code for this…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-15718`
- **CVE:** `CVE-2026-15719`
- **CVE:** `CVE-2026-15764`
- **CVE:** `CVE-2026-15765`
- **CVE:** `CVE-2026-48318`
- **CVE:** `CVE-2026-48322`
- **CVE:** `CVE-2026-48284`
- **CVE:** `CVE-2026-48321`
- **CVE:** `CVE-2026-48325`
- **CVE:** `CVE-2026-48319`
- **CVE:** `CVE-2026-48324`
- **CVE:** `CVE-2026-48327`
- **CVE:** `CVE-2026-48356`
- **CVE:** `CVE-2026-48358`
- **CVE:** `CVE-2026-48259`
- **CVE:** `CVE-2026-48359`
- **CVE:** `CVE-2026-47865`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-15718`, `CVE-2026-15719`, `CVE-2026-15764`, `CVE-2026-15765`, `CVE-2026-48318`, `CVE-2026-48322`, `CVE-2026-48284`, `CVE-2026-48321` _(+9 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
