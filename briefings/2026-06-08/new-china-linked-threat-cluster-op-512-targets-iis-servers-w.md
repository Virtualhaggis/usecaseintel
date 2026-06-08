# [LOW] New China-Linked Threat Cluster OP-512 Targets IIS Servers With Cryptographically Unique Web Shell Framework

**Source:** Cyber Security News
**Published:** 2026-06-08
**Article:** https://cybersecuritynews.com/new-china-linked-threat-cluster-op-512-targets-iis-servers/

## Threat Profile

A newly identified threat cluster with suspected ties to China has been caught targeting Internet Information Services (IIS) web servers using a purpose-built web shell framework. Tracked as OP-512, this group stands out for deploying tools designed to evade every detection method that works against similar China-linked actors. The discovery marks another escalation in a [&#8230;] The post New China-Linked Threat Cluster OP-512 Targets IIS Servers With Cryptographically Unique Web Shell Framewor…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `43.160.202.246`
- **IPv4 (defanged):** `140.206.161.227`
- **IPv4 (defanged):** `124.156.129.151`
- **Domain (defanged):** `ashx.lhlsjcb.com`
- **Domain (defanged):** `hcgos.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `43.160.202.246`, `140.206.161.227`, `124.156.129.151`, `ashx.lhlsjcb.com`, `hcgos.com`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
