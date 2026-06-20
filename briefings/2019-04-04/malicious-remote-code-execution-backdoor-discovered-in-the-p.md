# [HIGH] Malicious remote code execution backdoor discovered in the popular bootstrap-sass Ruby gem

**Source:** Snyk
**Published:** 2019-04-04
**Article:** https://snyk.io/blog/malicious-remote-code-execution-backdoor-discovered-in-the-popular-bootstrap-sass-ruby-gem/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
April 4, 2019
0 mins read On March 26, 2019, a malicious version of the popular bootstrap-sass package, that has been downloaded a total of 28 million times to date, was published to the official RubyGems repository. Version 3.2.0.3 includes a stealthy backdoor that gives attackers remote command execution on server-side Rails applications.
We have already added the vulnerability to our database, and if your project is being monitored by Snyk, you …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `366d6162fe36fc81dadc114558b43c6c8890c8bcc7e90e2949ae6344d0785dc0`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `366d6162fe36fc81dadc114558b43c6c8890c8bcc7e90e2949ae6344d0785dc0`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
