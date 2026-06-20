# [HIGH] Everything you wanted to know about addressing security vulnerabilities in Linux-based containers

**Source:** Snyk
**Published:** 2019-09-18
**Article:** https://snyk.io/blog/everything-you-wanted-to-know-about-addressing-security-vulnerabilities-in-linux-based-containers/

## Threat Profile

Snyk Blog In this article
Written by Karni Wolf 
Tomer Ezer 
September 18, 2019
0 mins read Think about the most important container image that you have running in production right now. How did you choose its base image? Do you know how many vulnerabilities that base image has? Wouldn’t you like to know?
Here at Snyk we try to make the process of choosing the most secure base image smarter, smoother and most importantly, more data-driven.
But first let’s start with some background about Linux di…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `fe8a0be91ee3e7dea812e8694491e1dde5b75e6d`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `fe8a0be91ee3e7dea812e8694491e1dde5b75e6d`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
