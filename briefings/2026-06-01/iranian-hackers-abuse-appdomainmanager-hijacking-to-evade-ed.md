# [LOW] Iranian Hackers Abuse AppDomainManager Hijacking to Evade EDR Detection

**Source:** Cyber Security News
**Published:** 2026-06-01
**Article:** https://cybersecuritynews.com/iranian-hackers-abuse-appdomainmanager-hijacking/

## Threat Profile

Iranian hackers have taken their cyberespionage playbook to a new level, deploying a sophisticated .NET hijacking technique to slip past endpoint defenses and target organizations across the United States, Israel, and the United Arab Emirates. The campaign intensified following a regional conflict that began on February 28, 2026, attributed to an Iran-linked advanced persistent threat [&#8230;] The post Iranian Hackers Abuse AppDomainManager Hijacking to Evade EDR Detection appeared first on Cyb…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `buisness-centeral-transportation.com`
- **Domain (defanged):** `premierhealthadvisory.com`
- **Domain (defanged):** `ramiltonsfinance.com`
- **Domain (defanged):** `business-startup.org`
- **Domain (defanged):** `docspace-y4cumb.onlyoffice.com`
- **Domain (defanged):** `docspace-twpf0e.onlyoffice.com`
- **SHA256:** `44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250`
- **SHA256:** `332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17`
- **SHA256:** `0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864`
- **SHA256:** `38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d`
- **SHA256:** `d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2`
- **SHA256:** `bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad`
- **SHA256:** `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27`
- **SHA256:** `9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84`
- **SHA256:** `b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4`
- **SHA256:** `8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b`
- **SHA256:** `43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa`
- **SHA256:** `9e4a658e6d831c9e9bdfe11884a75b7c64812ed0a80e8495ddf6b316505acac1`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `buisness-centeral-transportation.com`, `premierhealthadvisory.com`, `ramiltonsfinance.com`, `business-startup.org`, `docspace-y4cumb.onlyoffice.com`, `docspace-twpf0e.onlyoffice.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250`, `332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17`, `0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864`, `38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d`, `d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2`, `bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad`, `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27`, `9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84` _(+4 more)_


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
