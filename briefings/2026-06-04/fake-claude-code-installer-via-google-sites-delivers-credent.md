# [LOW] Fake Claude Code Installer Via Google Sites Delivers Credential-Stealing Malware

**Source:** Cyber Security News
**Published:** 2026-06-04
**Article:** https://cybersecuritynews.com/fake-claude-code-installer-via-google-sites/

## Threat Profile

Cybercriminals have found a new and clever way to exploit the growing popularity of AI developer tools. A recently identified campaign uses fake pages mimicking Claude Code and OpenAI Codex, hosted on trusted Google Sites infrastructure, to trick users into running commands that quietly steal their credentials and other sensitive personal data from their devices. [&#8230;] The post Fake Claude Code Installer Via Google Sites Delivers Credential-Stealing Malware appeared first on Cyber Security N…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.177.239.255`
- **Domain (defanged):** `sites.google.com/view/clau-ver-un-24`
- **Domain (defanged):** `download.version-516.com`
- **Domain (defanged):** `version-516.com`
- **Domain (defanged):** `oakenfjrod.ru`
- **Domain (defanged):** `download-version.1-5-8.com`
- **Domain (defanged):** `download.get-version.com`
- **SHA256:** `2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.177.239.255`, `sites.google.com/view/clau-ver-un-24`, `download.version-516.com`, `version-516.com`, `oakenfjrod.ru`, `download-version.1-5-8.com`, `download.get-version.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2b99ade9224add2ce86eb836dcf70040315f6dc95e772ea98f24a30cdf4fdb97`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
