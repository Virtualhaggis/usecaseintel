# [MED] Control Which Package Registries Your CI Jobs and Developer Machines Use

**Source:** StepSecurity
**Published:** 2026-08-12
**Article:** https://www.stepsecurity.io/blog/control-which-package-registries-your-ci-jobs-and-developer-machines-use

## Threat Profile

Back to Blog Product Control Which Package Registries Your CI Jobs and Developer Machines Use Two StepSecurity controls show every CI job and developer machine that still installs from public registries. Once you can see them, you can block public registries in CI and centrally set the registry configuration on every developer machine. Ashish Kurmi View LinkedIn August 11, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Everyo…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `94.154.172.43`
- **IPv4 (defanged):** `83.142.209.11`
- **IPv4 (defanged):** `46.151.182.203`
- **Domain (defanged):** `audit.checkmarx.cx`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `aquasecurtiy.org`
- **SHA256:** `18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb`
- **SHA256:** `8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14`
- **SHA256:** `167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `94.154.172.43`, `83.142.209.11`, `46.151.182.203`, `audit.checkmarx.cx`, `models.litellm.cloud`, `checkmarx.zone`, `aquasecurtiy.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb`, `8605e365edf11160aad517c7d79a3b26b62290e5072ef97b102a01ddbb343f14`, `167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
