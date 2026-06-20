# [HIGH] Fetch the Flag CTF 2022 writeup: Potty Training

**Source:** Snyk
**Published:** 2022-11-12
**Article:** https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-potty-training/

## Threat Profile

Snyk Blog In this article
Written by Mohammad-Ali A'râbi 
November 12, 2022
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF . And a huge thanks to the Snykers that built, tested, and wrote up the challenges! 
This post was written by Snyk Ambassador, Mohammad- Ali A’râbi ( @MohammadAliEN ) . Sign up to become a Snyk Ambassador today and get inside access to Snyk, including access to CTFs before they go live. 
The challenge (…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `dd67edb70a28335068dd5ea9304007b69543357ff471b3144e3355bca34cb35d`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `dd67edb70a28335068dd5ea9304007b69543357ff471b3144e3355bca34cb35d`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
