# [MED] PirloTV sports piracy network disrupted as 44 domains seized

**Source:** BleepingComputer
**Published:** 2026-06-25
**Article:** https://www.bleepingcomputer.com/news/security/pirlotv-sports-piracy-network-disrupted-as-44-domains-seized/

## Threat Profile

PirloTV sports piracy network disrupted as 44 domains seized 
By Bill Toulas 
June 25, 2026
11:36 AM
0 
A major sports piracy ring linked to the illegal PirloTV streaming platform has been disrupted in an action that targeted 44 domains.
PirloTV is a network of websites that aggregate and embed links to unauthorized live sports streams, primarily soccer, replaying feeds from various licensed broadcasters, depending on the event.
The platform, which does not stream content directly, is notorious …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `pirlotv2.pl`
- **Domain (defanged):** `pirlotv3.pl`
- **Domain (defanged):** `rojadirectaenvivo.pl`
- **Domain (defanged):** `elitegoltv.pl`
- **Domain (defanged):** `pirlotvplay.pl`
- **Domain (defanged):** `pirlotvplay.dev`
- **Domain (defanged):** `rojadirectahd.vip`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `pirlotv2.pl`, `pirlotv3.pl`, `rojadirectaenvivo.pl`, `elitegoltv.pl`, `pirlotvplay.pl`, `pirlotvplay.dev`, `rojadirectahd.vip`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
