# [HIGH] Coruna: the framework used in Operation Triangulation

**Source:** Securelist (Kaspersky)
**Published:** 2026-03-26
**Article:** https://securelist.com/coruna-framework-updated-operation-triangulation-exploit/119228/

## Threat Profile

Table of Contents
Introduction 
Technical details 
Safari 
Payload 
Kernel exploits 
Launcher 
Conclusions 
Authors
Boris Larin 
Introduction 
On March 4, 2026, Google and iVerify published reports about a highly sophisticated exploit kit targeting Apple iPhone devices. According to Google, the exploit kit was first discovered in targeted attacks conducted by a customer of an unnamed surveillance vendor. It was later used by other attackers in watering-hole attacks in Ukraine and in financially …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-32434`
- **CVE:** `CVE-2023-38606`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-32434`, `CVE-2023-38606`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
