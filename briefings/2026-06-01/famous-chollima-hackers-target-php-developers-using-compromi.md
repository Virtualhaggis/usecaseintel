# [LOW] Famous Chollima Hackers Target PHP Developers Using Compromised Packagist Package

**Source:** Cyber Security News
**Published:** 2026-06-01
**Article:** https://cybersecuritynews.com/famous-chollima-hackers-target-php-developers/

## Threat Profile

A well-known North Korean threat actor has been caught hiding malware inside a legitimate PHP package available through Packagist, the main package repository for PHP projects. The attack takes direct aim at software developers, disguising a dangerous payload as a routine configuration file. This kind of campaign blends in easily with normal development workflows, making [&#8230;] The post Famous Chollima Hackers Target PHP Developers Using Compromised Packagist Package appeared first on Cyber S…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `packagist.org/packages/roberts/leads`
- **Domain (defanged):** `github.com/roberts/leads`
- **SHA256:** `522b28a2f78771715497ba53729d4ab9a50e982322c391379f3bddf7c8cb363f`
- **SHA256:** `96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `packagist.org/packages/roberts/leads`, `github.com/roberts/leads`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `522b28a2f78771715497ba53729d4ab9a50e982322c391379f3bddf7c8cb363f`, `96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
