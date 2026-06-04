# [LOW] Proofpoint Warns TA4922 Deploys Atlas RAT, RomulusLoader, SilentRunLoader, and ValleyRAT

**Source:** Cyber Security News
**Published:** 2026-06-04
**Article:** https://cybersecuritynews.com/proofpoint-warns-ta4922-deploys-atlas-rat/

## Threat Profile

A sophisticated cybercrime group known as TA4922 is raising alarms across the global security community. The group has been deploying a growing arsenal of malware, including Atlas RAT, RomulusLoader, SilentRunLoader, and ValleyRAT, against organizations in Japan, the United Kingdom, Germany, and across Southeast Asia. These campaigns are financially motivated and show a level of planning [&#8230;] The post Proofpoint Warns TA4922 Deploys Atlas RAT, RomulusLoader, SilentRunLoader, and ValleyRAT a…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `206.238.115.58`
- **IPv4 (defanged):** `154.211.86.110`
- **IPv4 (defanged):** `43.156.77.97`
- **IPv4 (defanged):** `103.214.172.33`
- **IPv4 (defanged):** `18.139.83.110`
- **Domain (defanged):** `aeya388.club`
- **Domain (defanged):** `ws.ztts88.cyou`
- **Domain (defanged):** `nwphotoblog.com`
- **SHA256:** `a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295`
- **SHA256:** `584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8`
- **SHA256:** `66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d`
- **SHA256:** `4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d`
- **SHA256:** `a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad`
- **SHA256:** `40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5`
- **SHA256:** `8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0`
- **SHA256:** `3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d`
- **SHA256:** `314f4b59535d1b783e1c20c2be00f9e30f8ed27b2e21fad06a73b47ea43279ef`
- **SHA256:** `2d2a251a88632f010fd9671789746908eeccaa5bc5c0a5d25e4649efe4f5b15d`
- **SHA256:** `e0a6a71c605d9a4076147e9537f82f79f1e1eccadc874595160aa4637ff4088c`
- **SHA256:** `de82998ad5fcd63deae030803388e0fb4290d6223fda82368fd25b99b823f0d2`
- **SHA256:** `9d0a55c545c4147956db2c2667c4ed931a2875309147548b1dfdd216228f5f73`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `206.238.115.58`, `154.211.86.110`, `43.156.77.97`, `103.214.172.33`, `18.139.83.110`, `aeya388.club`, `ws.ztts88.cyou`, `nwphotoblog.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a648db354820ea4d02940cb1702b35974513b7aae83f6dffaacaac4ba31f9295`, `584a9448dda46bd590d7a2f86228100d2ae6e0d6d990c1a4459ed5ee28e07ae8`, `66a3836b9a17771bce2161f6b73cbc2494a91e49d6aa30d2d53711e8d10de60d`, `4fcfa88fffacbce30bbe2136753c9ab5a4c092940d2406fd9d44d5118e745b9d`, `a75eab31d7ff06b6864960ad7e633be3f9730ff3d3873e4539c8f425fc632dad`, `40b41979b317406f8abc601677a3b93aaf6ef8ab8ac188b8f383735e388f13b5`, `8c9b6542f73c5c7fe455b52f5101314407da4f65ff48e7ebf6896605e607c8d0`, `3119cf37b8267db8a2dcd11d9a83d5237d7ef1e42388e7c9afa2831b91da8a2d` _(+5 more)_


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
