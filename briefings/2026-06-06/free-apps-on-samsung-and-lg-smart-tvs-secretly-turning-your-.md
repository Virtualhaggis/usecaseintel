# [LOW] Free Apps on Samsung and LG Smart TVs Secretly Turning Your Devices Into AI Proxies

**Source:** Cyber Security News
**Published:** 2026-06-06
**Article:** https://cybersecuritynews.com/free-apps-turning-smart-tvs-into-proxies/

## Threat Profile

Free apps available on Samsung, LG, Roku, and other major smart TV platforms have been quietly enrolling millions of living room devices into a commercial residential proxy network used to scrape web data for AI training all through a consent dialog buried in a TV remote&#8217;s arrow-key navigation, according to new research from Include Security. [&#8230;] The post Free Apps on Samsung and LG Smart TVs Secretly Turning Your Devices Into AI Proxies appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `3.33.193.183`
- **IPv4 (defanged):** `15.197.193.114`
- **Domain (defanged):** `proxyjs.brdtnet.com`
- **Domain (defanged):** `proxyjs.luminatinet.com`
- **Domain (defanged):** `proxyjs.bright-sdk.com`
- **Domain (defanged):** `clientsdk.bright-sdk.com`
- **Domain (defanged):** `clientsdk.brdtnet.com`
- **Domain (defanged):** `brdtnet.com`
- **Domain (defanged):** `luminatinet.com`
- **Domain (defanged):** `luminati.io`
- **Domain (defanged):** `bright-sdk.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `3.33.193.183`, `15.197.193.114`, `proxyjs.brdtnet.com`, `proxyjs.luminatinet.com`, `proxyjs.bright-sdk.com`, `clientsdk.bright-sdk.com`, `clientsdk.brdtnet.com`, `brdtnet.com` _(+3 more)_


## Why this matters

Severity classified as **LOW** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
