# [MED] New Gafgyt Variant Targets Multiple Linux Architectures With Modular Propagation

**Source:** Cyber Security News
**Published:** 2026-06-05
**Article:** https://cybersecuritynews.com/new-gafgyt-variant-targets-multiple-linux-architectures/

## Threat Profile

A newly discovered variant of the Gafgyt botnet malware, named C0XMO, has been quietly spreading across Linux-based devices by targeting a known vulnerability in DD-WRT router firmware. The malware exploits a stack buffer overflow flaw in the UPnP service of affected routers, letting attackers gain full access without any credentials. Once inside, it works to [&#8230;] The post New Gafgyt Variant Targets Multiple Linux Architectures With Modular Propagation appeared first on Cyber Security News …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-27137`
- **CVE:** `CVE-2015-2051`
- **CVE:** `CVE-2022-35914`
- **CVE:** `CVE-2016-15047`
- **CVE:** `CVE-2025-34054`
- **IPv4 (defanged):** `85.215.131.70`
- **IPv4 (defanged):** `217.160.125.125`
- **IPv4 (defanged):** `176.100.37.91`
- **SHA256:** `444a9d34a9f59dc7975dfabefb47d789813a4497bbac9127c4806dd816e85211`
- **SHA256:** `9394666007fac4014a4641fdae150c1b969ed2bc4299876318a336fd386abf59`
- **SHA256:** `450ea44da0c9d96a2e8f4d6bad34f1c35cd35743295b8cd2defa9f7a9884685d`
- **SHA256:** `d452f22dacab9785539484245c13e9cce58df23fc82eeef205684fcd196da20b`
- **SHA256:** `20042f1efb59c99e3addf822a3e9e5a496f0b701362df038a50a32a9f504a136`
- **SHA256:** `7413cbb6eab4d6b10346f71be5dd76d7cf2f4817f7776367b162f83755aefa1f`
- **SHA256:** `b6f835ced11059d341222eba11fff3a4672f4de47a3a4d791fad86059a2b06d4`
- **SHA256:** `b61a5508847a2167b737d31193dc393e92c5be2aa5141bbe4b7ea6f440fd4799`
- **SHA256:** `dff0edae6e8854ddd3e617054ee0bd74c696c91411f704dff60aabaec839bec9`
- **SHA256:** `ea44138b9701fce1b2fe13de8f9e00681c007c9adc625edc9f507f177704c2e8`
- **SHA256:** `3ddb67ab079509dd1e7ac77fc4cfed25a271526668c68f8a2221e96a4cc21812`
- **SHA256:** `f02b1d8010dac35b007796def0cbd5d0c9414df790e2b55b105c95df2f2ffa91`
- **SHA256:** `8fc2d35b66c692d37a85ae9d30dc5c7f06f0b3eaf01112a5a6398a1a0feb3aee`
- **SHA256:** `eead44c0af7ddb12cece7b6125cf213bab3c22511cd59aff9d63dcfddb7d4386`
- **SHA256:** `41e8e327abbf2ba721be677ad8a416a7295708257b39688a0af03275fb199cec`

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
  - CVE(s): `CVE-2021-27137`, `CVE-2015-2051`, `CVE-2022-35914`, `CVE-2016-15047`, `CVE-2025-34054`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `85.215.131.70`, `217.160.125.125`, `176.100.37.91`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `444a9d34a9f59dc7975dfabefb47d789813a4497bbac9127c4806dd816e85211`, `9394666007fac4014a4641fdae150c1b969ed2bc4299876318a336fd386abf59`, `450ea44da0c9d96a2e8f4d6bad34f1c35cd35743295b8cd2defa9f7a9884685d`, `d452f22dacab9785539484245c13e9cce58df23fc82eeef205684fcd196da20b`, `20042f1efb59c99e3addf822a3e9e5a496f0b701362df038a50a32a9f504a136`, `7413cbb6eab4d6b10346f71be5dd76d7cf2f4817f7776367b162f83755aefa1f`, `b6f835ced11059d341222eba11fff3a4672f4de47a3a4d791fad86059a2b06d4`, `b61a5508847a2167b737d31193dc393e92c5be2aa5141bbe4b7ea6f440fd4799` _(+7 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
