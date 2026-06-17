# [MED] FishMonger Hackers Expands SprySOCKS Backdoor From Linux to Windows With Advanced Stealth Features

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/fishmonger-hackers-expands-sprysocks-backdoor-from-linux/

## Threat Profile

A well-known Chinese cyberespionage group has taken a major step forward in its hacking capabilities. The threat actor, tracked as FishMonger, has brought its SprySOCKS backdoor to Windows for the first time, after years of deploying it exclusively on Linux. This upgrade signals the group is broadening its reach and is now capable of targeting [&#8230;] The post FishMonger Hackers Expands SprySOCKS Backdoor From Linux to Windows With Advanced Stealth Features appeared first on Cyber Security New…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-24932`
- **IPv4 (defanged):** `207.148.78.36`
- **IPv4 (defanged):** `207.148.75.122`
- **SHA1:** `955BFC3DCC867256F9F46A606DEB0779FA3416D8`
- **SHA1:** `44DC4A08C5EB0972C8E18B0E01284E06F09006BB`
- **SHA1:** `AB87B29B6F79487C75CA08D102E79001E536F083`
- **SHA1:** `6490B8E4AADE25A3EE2DA9A47F312DB2122470BC`
- **SHA1:** `E7484C24B88A1A2407A8F09D734F9A993670285B`
- **SHA1:** `621D1952839BE4B0A1B0E66E87BCE5062CA368ED`
- **SHA1:** `2457EED2AB28E37741F10914EF929DAD2C8079D4`
- **SHA1:** `D2C706B1EAF662BF0CE124B5032F73ED84BDA24A`
- **SHA1:** `5F3B87CEF56683D9A9E19186E0FD0D8019B559C4`
- **SHA1:** `C793CA31E3F6628B5C8986146953BF66232E9A30`
- **SHA1:** `037DB2445F3D72388CB2CF8510563148E5A184BE`
- **SHA1:** `FFC3AA7909D4E72C360D65A1F45260DFFE5C99B7`

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
  - CVE(s): `CVE-2023-24932`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `207.148.78.36`, `207.148.75.122`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `955BFC3DCC867256F9F46A606DEB0779FA3416D8`, `44DC4A08C5EB0972C8E18B0E01284E06F09006BB`, `AB87B29B6F79487C75CA08D102E79001E536F083`, `6490B8E4AADE25A3EE2DA9A47F312DB2122470BC`, `E7484C24B88A1A2407A8F09D734F9A993670285B`, `621D1952839BE4B0A1B0E66E87BCE5062CA368ED`, `2457EED2AB28E37741F10914EF929DAD2C8079D4`, `D2C706B1EAF662BF0CE124B5032F73ED84BDA24A` _(+4 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
