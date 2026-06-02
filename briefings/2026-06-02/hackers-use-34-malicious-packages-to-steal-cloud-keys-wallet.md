# [MED] Hackers Use 34 Malicious Packages to Steal Cloud Keys, Wallets, and SSH Credentials

**Source:** Cyber Security News
**Published:** 2026-06-02
**Article:** https://cybersecuritynews.com/hackers-use-34-malicious-packages/

## Threat Profile

Hackers have planted 34 malicious packages across three major open-source ecosystems, quietly stealing cloud credentials, SSH keys, and blockchain wallet data from developers who never suspected a thing. The campaign, named TrapDoor, was first disclosed on May 24, 2026 by the security research team at Socket.dev, who found the poisoned packages spread across npm, PyPI, [&#8230;] The post Hackers Use 34 Malicious Packages to Steal Cloud Keys, Wallets, and SSH Credentials appeared first on Cyber S…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `ddjidd564.github.io`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `ddjidd564.github.io`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
