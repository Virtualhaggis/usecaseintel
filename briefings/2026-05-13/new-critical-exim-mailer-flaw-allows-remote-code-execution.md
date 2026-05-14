# [HIGH] New critical Exim mailer flaw allows remote code execution

**Source:** BleepingComputer
**Published:** 2026-05-13
**Article:** https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/

## Threat Profile

New critical Exim mailer flaw allows remote code execution 
By Bill Toulas 
May 13, 2026
04:23 PM
0 
A critical vulnerability affecting certain configurations of the Exim open-source mail transfer agent could be exploited by an unauthenticated remote attacker to execute arbitrary code.
Identified as CVE-2026-45185 , the security issue impacts some Exim versions before 4.99.3 that use the default GNU Transport Layer Security (GnuTLS) library for secure communication. It is a user-after-free (UAF)…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45185`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45185`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
