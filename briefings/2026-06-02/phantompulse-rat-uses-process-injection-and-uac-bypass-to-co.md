# [LOW] PHANTOMPULSE RAT Uses Process Injection and UAC Bypass to Compromise Windows Systems

**Source:** Cyber Security News
**Published:** 2026-06-02
**Article:** https://cybersecuritynews.com/phantompulse-rat-uses-process-injection-and-uac-bypass/

## Threat Profile

A newly analyzed remote access trojan called PHANTOMPULSE has drawn serious attention for its advanced approach to compromising Windows systems. The malware is the final-stage payload in a broader attack chain known as REF6598, a threat cluster actively targeting the cryptocurrency sector. What makes PHANTOMPULSE particularly dangerous is how it chains multiple advanced techniques together [&#8230;] The post PHANTOMPULSE RAT Uses Process Injection and UAC Bypass to Compromise Windows Systems app…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `195.3.222.251`
- **Domain (defanged):** `panel.fefea22134.net`
- **Domain (defanged):** `0x666.info`
- **Domain (defanged):** `thoroughly-publisher-troy-clara.trycloudflare.com`
- **SHA256:** `70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980`
- **SHA256:** `33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `195.3.222.251`, `panel.fefea22134.net`, `0x666.info`, `thoroughly-publisher-troy-clara.trycloudflare.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `70bbb38b70fd836d66e8166ec27be9aa8535b3876596fc80c45e3de4ce327980`, `33dacf9f854f636216e5062ca252df8e5bed652efd78b86512f5b868b11ee70f`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
