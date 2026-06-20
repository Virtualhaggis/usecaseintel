# [MED] Fetch the Flag CTF 2022 writeup: Not So Smart Fridge

**Source:** Snyk
**Published:** 2022-11-10
**Article:** https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-not-so-smart-fridge/

## Threat Profile

Snyk Blog In this article
Written by Antonio Gomes 
November 10, 2022
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF . And a huge thanks to the Snykers that built, tested, and wrote up the challenges! 
This Fetch the Flag CTF challenge starts with a warm welcome, giving us all the necessary information about our shiny new Smart Fridge Ultra SFU-3000 ! Exciting, right?
Isaac Asimov once predicted, “Whole, semi-prepared meals…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-26068`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-26068`


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
