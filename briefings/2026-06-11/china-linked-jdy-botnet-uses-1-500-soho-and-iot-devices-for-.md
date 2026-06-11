# [MED] China-Linked JDY Botnet Uses 1,500+ SOHO and IoT Devices for Rapid Vulnerability Exploitation

**Source:** Cyber Security News
**Published:** 2026-06-11
**Article:** https://cybersecuritynews.com/china-linked-jdy-botnet-uses-1500-soho-and-iot-devices/

## Threat Profile

A China-linked network of compromised routers and smart devices has grown into one of the most capable reconnaissance tools tied to a nation-state threat group. Researchers have identified a major resurgence of a botnet known as JDY, which now controls more than 1,500 small office and home office (SOHO) and Internet of Things (IoT) devices [&#8230;] The post China-Linked JDY Botnet Uses 1,500+ SOHO and IoT Devices for Rapid Vulnerability Exploitation appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35616`
- **IPv4 (defanged):** `149.248.3.38`
- **IPv4 (defanged):** `23.27.120.240`
- **IPv4 (defanged):** `109.104.154.116`
- **IPv4 (defanged):** `216.173.65.250`
- **IPv4 (defanged):** `194.14.217.88`
- **SHA256:** `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf`
- **SHA256:** `03c4667f016f1e8441177639d87f77a59f32d2c7e0041616376967338667bd3b`
- **SHA256:** `1e0da906811b570c4134ade310c3a94631d4b308d27b616497266b49aae2ad0a`
- **SHA256:** `d62055910cd579ff1fb57bd1926c5b2e80e1677f0316737b2f733f86b01615dc`
- **SHA256:** `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed`
- **SHA256:** `28a23ab78739de674f94d9acadfe0709862c2b2d947e9051b200a24d3f9f45c4`
- **SHA256:** `d1414803a83b1ba260e3e1be742379eccbb806f987ec1e7c0bc5399e4971a58f`
- **SHA256:** `96ecc107aa645e36b5f939ebfcf9e61fc9ebc27616680fbd0fdeb41c7950d79a`

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
  - CVE(s): `CVE-2026-35616`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `149.248.3.38`, `23.27.120.240`, `109.104.154.116`, `216.173.65.250`, `194.14.217.88`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf`, `03c4667f016f1e8441177639d87f77a59f32d2c7e0041616376967338667bd3b`, `1e0da906811b570c4134ade310c3a94631d4b308d27b616497266b49aae2ad0a`, `d62055910cd579ff1fb57bd1926c5b2e80e1677f0316737b2f733f86b01615dc`, `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed`, `28a23ab78739de674f94d9acadfe0709862c2b2d947e9051b200a24d3f9f45c4`, `d1414803a83b1ba260e3e1be742379eccbb806f987ec1e7c0bc5399e4971a58f`, `96ecc107aa645e36b5f939ebfcf9e61fc9ebc27616680fbd0fdeb41c7950d79a`


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
