# [MED] Real-time threat protection with Snyk and SentinelOne

**Source:** Snyk
**Published:** 2023-11-09
**Article:** https://snyk.io/blog/snyk-sentinelone-built-time-runtime-solution/

## Threat Profile

Snyk Blog In this article
Written by Shivam Jindal 
November 9, 2023
0 mins read Modern applications are made up of more than first-party code and third-party dependencies. Even a single application links back to a vast ecosystem of cloud environments, containers, third-party base images, and automated container orchestration.
Along with the ability to build applications faster, developers also need to secure code and associated dependencies, deployment configuration, and containers running in p…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `us-east-2.compute.internal`
- **SHA1:** `8656c04d40b0b3900721ddf26ea43c5f5f646b7b`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `us-east-2.compute.internal`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8656c04d40b0b3900721ddf26ea43c5f5f646b7b`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
