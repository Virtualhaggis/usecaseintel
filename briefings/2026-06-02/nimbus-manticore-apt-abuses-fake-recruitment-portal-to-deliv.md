# [MED] Nimbus Manticore APT Abuses Fake Recruitment Portal to Deliver Custom Malware

**Source:** Cyber Security News
**Published:** 2026-06-02
**Article:** https://cybersecuritynews.com/nimbus-manticore-apt-abuses-fake-recruitment-portal/

## Threat Profile

A state-linked hacking group has been caught running a carefully crafted fake recruitment operation to push custom malware onto unsuspecting victims. The group, known as Nimbus Manticore and also tracked as UNC1549 and Smoke Sandstorm, has a long history of targeting professionals in the aerospace and defense sectors across the Middle East and Europe. Their [&#8230;] The post Nimbus Manticore APT Abuses Fake Recruitment Portal to Deliver Custom Malware appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `ebix.recruitment-flow.com`
- **Domain (defanged):** `boeing-careers.com`
- **Domain (defanged):** `rheinmetallcareer.org`
- **Domain (defanged):** `airbus.global-careers.com`
- **Domain (defanged):** `flydubaicareers.ae.org`
- **Domain (defanged):** `telespazio-careers.com`
- **Domain (defanged):** `arabiccountriestalent.com`
- **SHA256:** `23c0b4f1733284934c071df2bf953a1a894bb77c84cff71d9bfcf80ce3dc4c16`
- **SHA256:** `0b2c137ef9087cb4635e110f8e12bb0ed43b6d6e30c62d1f880db20778b73c9a`
- **SHA256:** `6780116ec3eb7d26cf721607e14f352957a495d97d74234aade67adbdc3ed339`
- **SHA256:** `95d246e4956ad5e6b167a3d9d939542d6d80ec7301f337e00bb109cc220432cf`
- **SHA256:** `9b186530f291f0e6ebc981399c956e1de3ba26b0315b945a263250c06831f281`
- **SHA256:** `06d12a4c4e3cc725dba37445cebeba41803718ccdb63d9d637355a241f651668`
- **SHA256:** `9b63b744dc1f3a24f057a404c5622ed0ca933752a00ce05117727c7d11f05536`
- **SHA256:** `620c51f4376cb79f0109c21971c28661418ae50b119585e3ffdb8011189fcb7b`
- **SHA256:** `d1f525eb9347133b92e9558e1413558c8348c0f35a62577f60a5192ba38eb776`
- **SHA256:** `eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71`
- **SHA256:** `dfa1e3137a032ee8561a1cd5e1a0f71a10bebb36aef7c336c878638a9c1239ee`
- **SHA256:** `8e5fc0998838559ca8611e6c03fd998a17ffc2eade24715b2fc3e723c712eb8b`
- **SHA256:** `3628d13d2f8af7663d58dd1aa352c8f12d12233a7318ee203f01f195573a2ed2`
- **SHA256:** `c7ef2ec19d158301773b1590f5b5eeb362a30f725acad8f5b3a230e9f26d14be`
- **SHA256:** `072744ce205bb89a36e563a86f30df5689e64eee75106b97ce708551c8194bbc`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `ebix.recruitment-flow.com`, `boeing-careers.com`, `rheinmetallcareer.org`, `airbus.global-careers.com`, `flydubaicareers.ae.org`, `telespazio-careers.com`, `arabiccountriestalent.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `23c0b4f1733284934c071df2bf953a1a894bb77c84cff71d9bfcf80ce3dc4c16`, `0b2c137ef9087cb4635e110f8e12bb0ed43b6d6e30c62d1f880db20778b73c9a`, `6780116ec3eb7d26cf721607e14f352957a495d97d74234aade67adbdc3ed339`, `95d246e4956ad5e6b167a3d9d939542d6d80ec7301f337e00bb109cc220432cf`, `9b186530f291f0e6ebc981399c956e1de3ba26b0315b945a263250c06831f281`, `06d12a4c4e3cc725dba37445cebeba41803718ccdb63d9d637355a241f651668`, `9b63b744dc1f3a24f057a404c5622ed0ca933752a00ce05117727c7d11f05536`, `620c51f4376cb79f0109c21971c28661418ae50b119585e3ffdb8011189fcb7b` _(+7 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
