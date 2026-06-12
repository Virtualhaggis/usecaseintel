# [HIGH] Fancy Bear Hackers Abuse EdgeRouters and Cloud Services to Launch Stealthy Cyberattacks

**Source:** Cyber Security News
**Published:** 2026-06-12
**Article:** https://cybersecuritynews.com/fancy-bear-hackers-abuse-edgerouters-and-cloud-services/

## Threat Profile

One of the most persistent hacking groups in the world has found a new way to stay hidden. The threat actor known as Fancy Bear, formally tracked as APT28 and attributed to Russia&#8217;s military intelligence unit GRU Unit 26165, has been quietly shifting how it runs cyberattack operations. Instead of relying on traditional infrastructure, the [&#8230;] The post Fancy Bear Hackers Abuse EdgeRouters and Cloud Services to Launch Stealthy Cyberattacks appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-21509`
- **CVE:** `CVE-2023-50224`
- **Domain (defanged):** `freefoodaid.com`
- **Domain (defanged):** `wellnesscaremed.com`
- **Domain (defanged):** `wellnessmedcare.org`
- **Domain (defanged):** `longsauce.com`
- **SHA256:** `b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546`
- **SHA256:** `1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50`
- **SHA256:** `5a17cfaea0cc3a82242fdd11b53140c0b56256d769b07c33757d61e0a0a6ec02`
- **SHA256:** `fd3f13db41cd5b442fa26ba8bc0e9703ed243b3516374e3ef89be71cbf07436b`
- **SHA256:** `c91183175ce77360006f964841eb4048cf37cb82103f2573e262927be4c7607f`
- **SHA256:** `a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee`
- **SHA256:** `bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e`
- **SHA256:** `0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e`
- **SHA256:** `a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1`
- **SHA256:** `2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9`
- **SHA256:** `9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8`
- **SHA256:** `3f476d316efe2514efd70c975d0c87e12357db9fca54a25834d60b28192c6a69`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-21509`, `CVE-2023-50224`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `freefoodaid.com`, `wellnesscaremed.com`, `wellnessmedcare.org`, `longsauce.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546`, `1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50`, `5a17cfaea0cc3a82242fdd11b53140c0b56256d769b07c33757d61e0a0a6ec02`, `fd3f13db41cd5b442fa26ba8bc0e9703ed243b3516374e3ef89be71cbf07436b`, `c91183175ce77360006f964841eb4048cf37cb82103f2573e262927be4c7607f`, `a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee`, `bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e`, `0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e` _(+4 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
