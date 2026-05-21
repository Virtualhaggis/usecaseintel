# [HIGH] AI Is Building Your Attack Surface. Are You Testing It?

**Source:** Snyk
**Published:** 2026-03-19
**Article:** https://snyk.io/blog/ai-is-building-your-attack-surface-are-you-testing-it/

## Threat Profile

Snyk Blog In this article
Written by Manoj Nair 
March 19, 2026
0 mins read The market is flooded with claims. One vendor tops a leaderboard. Another raises nine figures on a pitch deck. Meanwhile, your developers shipped three AI-generated services before lunch. Here's the conversation the industry isn't having, and the one we've been building toward for years. 
There's a version of this conversation happening inside every Security team right now.
Someone demos an AI coding assistant. The speed…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-12420`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-12420`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
