# [LOW] New Pink Hacking Group Attacking Enterprise Users to Steal Cloud Storage Passwords

**Source:** Cyber Security News
**Published:** 2026-06-08
**Article:** https://cybersecuritynews.com/new-pink-hacking-group-attacking-enterprise-users/

## Threat Profile

A newly identified extortion group called Pink has emerged as a serious threat to enterprise organizations, using social engineering tactics to steal cloud storage credentials and sensitive data. The group, tracked under the cluster code CL-CRI-1147, launched its dedicated data leak site on May 31, 2026, and has already listed several initial victims. Security teams [&#8230;] The post New Pink Hacking Group Attacking Enterprise Users to Steal Cloud Storage Passwords appeared first on Cyber Secur…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.178.208.153`
- **IPv4 (defanged):** `172.93.100.252`
- **IPv4 (defanged):** `96.232.20.66`
- **Domain (defanged):** `passkeyadd.com`
- **Domain (defanged):** `passkeydeploy.com`
- **Domain (defanged):** `deploypasskey.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.178.208.153`, `172.93.100.252`, `96.232.20.66`, `passkeyadd.com`, `passkeydeploy.com`, `deploypasskey.com`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
