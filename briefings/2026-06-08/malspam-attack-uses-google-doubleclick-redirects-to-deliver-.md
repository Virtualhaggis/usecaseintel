# [LOW] Malspam Attack Uses Google DoubleClick Redirects to Deliver Fileless .NET Loader

**Source:** Cyber Security News
**Published:** 2026-06-08
**Article:** https://cybersecuritynews.com/malspam-attack-uses-google-doubleclick-redirects/

## Threat Profile

Cybercriminals have found a new way to sneak malware past email security tools, and this time they are hiding behind a name that most systems trust without question. A recent malspam campaign has been caught using Google&#8217;s own DoubleClick ad-tracking infrastructure to route victims toward a fileless .NET loader, a type of malware that runs [&#8230;] The post Malspam Attack Uses Google DoubleClick Redirects to Deliver Fileless .NET Loader appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `fostercareintheus.optimizationprime.com`
- **Domain (defanged):** `bth.startthewave.org`
- **Domain (defanged):** `pengajian.muliastudy.com`
- **Domain (defanged):** `andrefelipedonascime1778799406970.2241107.meusitehostgator.com.br`
- **Domain (defanged):** `catalogo.castrouria.com`
- **Domain (defanged):** `xtadts.ddns.net`
- **Domain (defanged):** `afxwd.ddns.net`
- **SHA256:** `d5b7247c497788cf0031ceb06e3df77a45fef59f1e49633dc7159816d64759b5`
- **SHA256:** `c61b1941cf756eb7551f7c661743802362728b785adc22e860d269713dfb01a6`
- **SHA256:** `c356aff1a01c2b0da472e584c8e3c8f875b9a24280435d42836a77b19f5a8c18`
- **SHA256:** `f1c3ebe78bd8c38559bf3cfcc9a9fa37d221e31780774a3787e26160a61f5348`
- **SHA256:** `e91fb249aa97be5c7931e430781167edfe7ba804720b5f643e6ab70b7e6e74dd`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `fostercareintheus.optimizationprime.com`, `bth.startthewave.org`, `pengajian.muliastudy.com`, `andrefelipedonascime1778799406970.2241107.meusitehostgator.com.br`, `catalogo.castrouria.com`, `xtadts.ddns.net`, `afxwd.ddns.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d5b7247c497788cf0031ceb06e3df77a45fef59f1e49633dc7159816d64759b5`, `c61b1941cf756eb7551f7c661743802362728b785adc22e860d269713dfb01a6`, `c356aff1a01c2b0da472e584c8e3c8f875b9a24280435d42836a77b19f5a8c18`, `f1c3ebe78bd8c38559bf3cfcc9a9fa37d221e31780774a3787e26160a61f5348`, `e91fb249aa97be5c7931e430781167edfe7ba804720b5f643e6ab70b7e6e74dd`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
