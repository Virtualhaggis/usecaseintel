# [MED] Rust Clipboard Hijacker Uses Fake GitHub Stars and VirusTotal Upvotes to Steal Crypto

**Source:** Cyber Security News
**Published:** 2026-06-18
**Article:** https://cybersecuritynews.com/rust-clipboard-hijacker-uses-fake-github-stars/

## Threat Profile

A newly discovered malware campaign is quietly draining cryptocurrency wallets by doing something most security tools never see coming. Instead of relying on brute-force attacks or dark web exploits, the threat actor behind this campaign built a fake reputation engine across multiple platforms to make dangerous software look completely safe and trustworthy. The malware at [&#8230;] The post Rust Clipboard Hijacker Uses Fake GitHub Stars and VirusTotal Upvotes to Steal Crypto appeared first on Cy…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `5518942d9d21794aaeff41a01b88606a96659fc329b481a2f0946d8163ab4d61`
- **SHA256:** `33c86ecfc324de3af97150bd009aba7925a6ba7a0842e127e94cf351013c0fe6`
- **SHA256:** `7a7ad4ae347a3f99f3773a113d9f70ecfa967100c96e8275bd1df833caee68d1`
- **SHA256:** `bad8625087a7b9453c70933c0db32518ff5818e3d83f3a9e78d432a22b383edb`
- **SHA256:** `c1435847b0c437f91efb07a3a35e4468036322d7acf4ba9e6d363cec0b481241`
- **SHA256:** `ef9a915c8e1d484e52b3287c94a58ecd22c07391a87f9c136eabd8397ed01ca2`
- **SHA256:** `e02e60a23297692637b43ebcd7dbeb63af1e9680c551586a1ce935218e0034be`
- **SHA256:** `fb8294b12f904dff2ac79b51872be7bf09ab422cde223caaf4762eadf7e0760d`
- **SHA256:** `a91c09e0eea610dbe5879798f9cf12e3ce51e4e6f0893278bcdf3ebe22c4730b`
- **SHA256:** `9c566db1ef9d08ee389d2b8cc1c50c65870096130c8bd2cf41ea14c4075e94c0`
- **SHA256:** `f737e99177cc05037ff34cf6e245dd56377dc3db4e2bb46edcf039df650939d6`
- **SHA256:** `7a9632bbecc31d02fdd0eab07e2424b3e1c9e9a3d91aac4ef6f708f2befbaa3d`
- **SHA256:** `b71efdebd0ca3563e67edb7ad59358a6b8f013b219ad65033efcf48fd1c86619`
- **SHA256:** `6f12c066a929c96104796c4ecca938754962009ebd9e4ba5329bb940bf331d0a`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5518942d9d21794aaeff41a01b88606a96659fc329b481a2f0946d8163ab4d61`, `33c86ecfc324de3af97150bd009aba7925a6ba7a0842e127e94cf351013c0fe6`, `7a7ad4ae347a3f99f3773a113d9f70ecfa967100c96e8275bd1df833caee68d1`, `bad8625087a7b9453c70933c0db32518ff5818e3d83f3a9e78d432a22b383edb`, `c1435847b0c437f91efb07a3a35e4468036322d7acf4ba9e6d363cec0b481241`, `ef9a915c8e1d484e52b3287c94a58ecd22c07391a87f9c136eabd8397ed01ca2`, `e02e60a23297692637b43ebcd7dbeb63af1e9680c551586a1ce935218e0034be`, `fb8294b12f904dff2ac79b51872be7bf09ab422cde223caaf4762eadf7e0760d` _(+6 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
