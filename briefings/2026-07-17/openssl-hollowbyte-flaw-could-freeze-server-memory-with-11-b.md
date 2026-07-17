# [HIGH] OpenSSL HollowByte Flaw Could Freeze Server Memory with 11-Byte TLS Requests

**Source:** The Hacker News
**Published:** 2026-07-17
**Article:** https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html

## Threat Profile

OpenSSL HollowByte Flaw Could Freeze Server Memory with 11-Byte TLS Requests 
 Swati Khandelwal  Jul 17, 2026 Vulnerability / Server Security 
Eleven bytes will make an unpatched OpenSSL server set aside up to 131 KB of memory for a message that never arrives. On the glibc systems Okta tested, that memory is gone until the process restarts.
OpenSSL shipped the HollowByte fix in June with no CVE, no advisory, and no changelog entry pointing at it. Okta's Red Team, which reported the denial-of-s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-34183`
- **CVE:** `CVE-2025-66199`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-34183`, `CVE-2025-66199`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
