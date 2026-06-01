# [LOW] Iran-Linked Hackers Destroy IT, Backups, and Recovery Systems in Cyberattack targeting Middle East

**Source:** Cyber Security News
**Published:** 2026-06-01
**Article:** https://cybersecuritynews.com/iran-linked-hackers-destroy-it-backups-and-recovery-systems/

## Threat Profile

Iran-linked hackers have launched a sweeping campaign of digital destruction across the United States and the Middle East, wiping IT systems, erasing backups, and dismantling recovery infrastructure at multiple organizations. The attacks, carried out under a pro-Iranian persona called &#8220;Ababil of Minab,&#8221; went far beyond data theft, leaving victims with little ability to restore their [&#8230;] The post Iran-Linked Hackers Destroy IT, Backups, and Recovery Systems in Cyberattack target…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `31.172.87.20`
- **IPv4 (defanged):** `212.83.61.213`
- **IPv4 (defanged):** `66.85.26.183`
- **IPv4 (defanged):** `195.20.17.129`
- **IPv4 (defanged):** `46.246.125.131`
- **IPv4 (defanged):** `146.70.233.83`
- **IPv4 (defanged):** `91.193.19.198`
- **IPv4 (defanged):** `89.36.231.56`
- **IPv4 (defanged):** `84.200.89.52`
- **IPv4 (defanged):** `46.30.190.173`
- **IPv4 (defanged):** `45.150.108.61`
- **Domain (defanged):** `nefeshhope.com`
- **Domain (defanged):** `members.nefeshhope.com`
- **Domain (defanged):** `feedback.nefeshhope.com`
- **Domain (defanged):** `banujcobaar.com`
- **SHA256:** `81a25357d027d0f04a43139377d5d58384b8e9b0770e699cdcc37e600641cf90`
- **SHA256:** `c8cc4225d1e21324ef419adbb1c10dd0578fb034b5f5d7b8000f0aae1871c061`
- **SHA256:** `33a6b4900c2fbfb3c2d816947871eade800d0c0e2a2680871700fd6e640e5f20`
- **SHA256:** `d76a94309240a7e2f11a89fab54a6853628e976a5ff19084b1b0894c89e6a742`
- **SHA256:** `f6db77be038980e9dbbf9f11e0f7ae7d2d4d3f1a53199958f1f55137dde5efd3`
- **SHA256:** `1c699720034367ba9761a8d31c854fd444e8e3c8c31c520a39c543cf95286029`
- **SHA256:** `38965a60835a5ee3eaefd3d0bffa97c0e4f0c5cd74d31d8053bedeea14f536ee`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `31.172.87.20`, `212.83.61.213`, `66.85.26.183`, `195.20.17.129`, `46.246.125.131`, `146.70.233.83`, `91.193.19.198`, `89.36.231.56` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `81a25357d027d0f04a43139377d5d58384b8e9b0770e699cdcc37e600641cf90`, `c8cc4225d1e21324ef419adbb1c10dd0578fb034b5f5d7b8000f0aae1871c061`, `33a6b4900c2fbfb3c2d816947871eade800d0c0e2a2680871700fd6e640e5f20`, `d76a94309240a7e2f11a89fab54a6853628e976a5ff19084b1b0894c89e6a742`, `f6db77be038980e9dbbf9f11e0f7ae7d2d4d3f1a53199958f1f55137dde5efd3`, `1c699720034367ba9761a8d31c854fd444e8e3c8c31c520a39c543cf95286029`, `38965a60835a5ee3eaefd3d0bffa97c0e4f0c5cd74d31d8053bedeea14f536ee`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
