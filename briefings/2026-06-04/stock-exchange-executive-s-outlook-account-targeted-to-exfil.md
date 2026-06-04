# [LOW] Stock Exchange Executive’s Outlook Account Targeted to Exfiltrate Credentials

**Source:** Cyber Security News
**Published:** 2026-06-04
**Article:** https://cybersecuritynews.com/stock-exchange-executives-outlook-account-targeted/

## Threat Profile

A senior executive at a major global stock exchange had their Microsoft Outlook account silently compromised for five straight months, with attackers carefully siphoning emails in small batches to avoid detection. The intrusion ran from October 2025 through at least March 2026, designed entirely around one single goal: stealing the complete contents of one person&#8217;s [&#8230;] The post Stock Exchange Executive’s Outlook Account Targeted to Exfiltrate Credentials appeared first on Cyber Secur…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `51.91.79.17`
- **Domain (defanged):** `temp.sh`
- **SHA256:** `db59813e3f27fb8608a4876e758f60b69d9700dc22d15237ac095bb3166fb622`
- **SHA256:** `1f385acf11f8ea6673d7295be6492ea9913b525da25dcc037ea49ef4f86a9d58`
- **SHA256:** `2587217bc685527480c803ddf34a56ae9d9bf02681828a8a2081acc775312cf3`
- **SHA256:** `6a69ea2ce3fea0ebfd7a32a1dfc4251bd4d7d8a4fbd44aaa47b82290d0414a9f`
- **SHA256:** `8b283c954d19a839a724961ccaf025c56988c4e745acb2d31a15a006cda072bf`
- **SHA256:** `d78f64551d1b31a31e5998e442f0debd458e011e05019b3951d9ddde997f8384`
- **SHA256:** `8c0871cd0f60bc603424e948a689945a1828d0bef926a6470ae18cf17d93f7cb`
- **SHA256:** `cf731b82c471211938b210ae8a6dcc7ece4f44371e716f056fa05151a9910727`
- **SHA256:** `acf5ed6e5bb90c44683938f35efeca551428064cdedbbaab8be69e3474fb806f`
- **SHA256:** `308351124c496d4f4effee65ab828506abf70385773c167ab1f32a7f030385ac`
- **SHA256:** `c3405d9c9d593d75d773c0615254e69d0362954384058ee970a3ec0944519c37`
- **SHA256:** `3b6cb20891bce8602ce669187754871e402a1782031ef8b032cd007e3894bc5d`
- **SHA256:** `d5e42104292513232d26ad7d9d317b5c779577da43e28fe27f8c2fb9318b0e8e`
- **SHA256:** `3aae5a24e63f3cb1ca4759b9e4ee8e503ff139189423f5fd8cc923c6819697ca`
- **SHA256:** `611db3195d55e871dce67ce5c41e894bbaab88dd0d019af68f5a259f0108aef7`
- **SHA256:** `eaff006ac0eb7f7fe4db5fc6a4b5b1dc272d83ced66d510dcea185b1278bb453`
- **SHA256:** `02048121fd0b3a51751ce7677155aa8818eba9d8ce67ea26fd1d7f43cfcdabd2`
- **SHA256:** `6c700ca4e6d917c7aa9d964e98604a0349d9b8b4673df96a3f73a3d2d042635a`
- **SHA256:** `f72a8b71f12eaab6518873f72ea4be4572d9f3fb8e8706ade3b9a7314f236f22`
- **SHA256:** `22f335a65c479c26019f6187dae290624117c82a702a96acbb04fa325f730d3e`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `51.91.79.17`, `temp.sh`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `db59813e3f27fb8608a4876e758f60b69d9700dc22d15237ac095bb3166fb622`, `1f385acf11f8ea6673d7295be6492ea9913b525da25dcc037ea49ef4f86a9d58`, `2587217bc685527480c803ddf34a56ae9d9bf02681828a8a2081acc775312cf3`, `6a69ea2ce3fea0ebfd7a32a1dfc4251bd4d7d8a4fbd44aaa47b82290d0414a9f`, `8b283c954d19a839a724961ccaf025c56988c4e745acb2d31a15a006cda072bf`, `d78f64551d1b31a31e5998e442f0debd458e011e05019b3951d9ddde997f8384`, `8c0871cd0f60bc603424e948a689945a1828d0bef926a6470ae18cf17d93f7cb`, `cf731b82c471211938b210ae8a6dcc7ece4f44371e716f056fa05151a9910727` _(+12 more)_


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
