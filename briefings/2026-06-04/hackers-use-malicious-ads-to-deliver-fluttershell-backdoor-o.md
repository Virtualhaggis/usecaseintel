# [LOW] Hackers Use Malicious Ads to Deliver FlutterShell Backdoor on macOS Systems

**Source:** Cyber Security News
**Published:** 2026-06-04
**Article:** https://cybersecuritynews.com/hackers-use-malicious-ads/

## Threat Profile

A new and rapidly spreading malware campaign is putting macOS users at serious risk. Threat actors are using Google Ads to push fake desktop applications that secretly install a powerful backdoor on infected machines. The campaign, dubbed Operation FlutterBridge, marks a sharp escalation in tactics from financially motivated attackers who have been active since at [&#8230;] The post Hackers Use Malicious Ads to Deliver FlutterShell Backdoor on macOS Systems appeared first on Cyber Security News …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `atsheisdomestic.org`
- **Domain (defanged):** `etoftheappyrince.org`
- **Domain (defanged):** `healightejustb.org`
- **Domain (defanged):** `sinterfumesco.com`
- **Domain (defanged):** `ads-parkpro.com`
- **Domain (defanged):** `adsparkpro.top`
- **Domain (defanged):** `adsparkpro.net`
- **Domain (defanged):** `softwe.art`
- **SHA256:** `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845`
- **SHA256:** `363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34`
- **SHA256:** `8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109`
- **SHA256:** `644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70`
- **SHA256:** `9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47`
- **SHA256:** `b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea`
- **SHA256:** `9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de`
- **SHA256:** `30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530`
- **SHA256:** `48047c34bbd57fe1e24bc538bc2ce9e0ac4c4eb48d3b0c195b414f0379dc0745`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `atsheisdomestic.org`, `etoftheappyrince.org`, `healightejustb.org`, `sinterfumesco.com`, `ads-parkpro.com`, `adsparkpro.top`, `adsparkpro.net`, `softwe.art`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845`, `363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34`, `8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109`, `644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70`, `9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47`, `b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea`, `9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de`, `30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530` _(+1 more)_


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
