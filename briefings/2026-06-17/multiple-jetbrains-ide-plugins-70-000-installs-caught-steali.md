# [LOW] Multiple JetBrains IDE Plugins 70,000+ Installs Caught Stealing AI keys

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/jetbrains-ide-plugins-installs-caught-stealing-ai-keys/

## Threat Profile

A large-scale malware campaign has been uncovered on the JetBrains Marketplace, where at least 15 malicious IDE plugins were found stealing sensitive API keys from developers. These plugins, downloaded over 70,000 times, were published under seven different vendor accounts and disguised as legitimate AI-powered coding assistants. According to Aikido’s research, the malicious plugins claimed to [&#8230;] The post Multiple JetBrains IDE Plugins 70,000+ Installs Caught Stealing AI keys appeared fir…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `39.107.60.51`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `39.107.60.51`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
