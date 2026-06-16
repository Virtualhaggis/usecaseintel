# [CRIT] Critical Fortinet FortiSandbox Vulnerabilities Actively Exploited in Attacks

**Source:** Cyber Security News
**Published:** 2026-06-16
**Article:** https://cybersecuritynews.com/fortinet-fortisandbox-vulnerabilities-exploit/

## Threat Profile

Threat actors are actively exploiting multiple critical vulnerabilities in Fortinet&#8217;s FortiSandbox platform, with live attack telemetry confirming exploitation attempts over the past 24 hours. Defused has flagged three CVEs under active targeting — including one, CVE-2026-39813, with no previously recorded exploitation history. Honeypot sensors and deception infrastructure disguised as Fortinet FortiSandbox instances have captured exploitation [&#8230;] The post Critical Fortinet FortiSand…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-39813`
- **CVE:** `CVE-2026-39808`
- **CVE:** `CVE-2026-25089`
- **IPv4 (defanged):** `141.11.43.175`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-39813`, `CVE-2026-39808`, `CVE-2026-25089`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `141.11.43.175`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
