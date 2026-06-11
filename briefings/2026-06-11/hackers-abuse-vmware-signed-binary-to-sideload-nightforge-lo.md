# [LOW] Hackers Abuse VMware-Signed Binary to Sideload NIGHTFORGE Loader in Espionage Attacks

**Source:** Cyber Security News
**Published:** 2026-06-11
**Article:** https://cybersecuritynews.com/hackers-abuse-vmware-signed-binary-to-sideload-nightforge-loader/

## Threat Profile

A newly uncovered espionage operation has been quietly targeting government institutions in Cambodia, and the method behind it is as clever as it is alarming. Threat actors have been abusing a legitimate, digitally signed VMware binary to slip a custom malicious loader called NIGHTFORGE onto victim systems. This technique, known as DLL sideloading, lets attackers [&#8230;] The post Hackers Abuse VMware-Signed Binary to Sideload NIGHTFORGE Loader in Espionage Attacks appeared first on Cyber Secur…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `193.150.240.37`
- **IPv4 (defanged):** `104.192.244.99`
- **SHA256:** `90bba96afe1b5b8410c4f1649adeb8ca1f04c816c64f46912d5bca890f8b2c0a`
- **SHA256:** `b34b34310b963fd2901b6e00b0e9a01be6c19d40e68101f0cc1d34ae7f22a4af`
- **SHA256:** `3a33a10901e9ef89eace7834f9c7ce14f590e58bb1b50ec5bd44b4ef1ca5555a`
- **SHA256:** `1852120a84a328edd1995e633dfd2009867898a8e3f0b385e2490cf21c77a994`
- **SHA256:** `b3e853eee14fb7948c6907888ee07139085ba9af4231c30e97ff6236b86ca024`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `193.150.240.37`, `104.192.244.99`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `90bba96afe1b5b8410c4f1649adeb8ca1f04c816c64f46912d5bca890f8b2c0a`, `b34b34310b963fd2901b6e00b0e9a01be6c19d40e68101f0cc1d34ae7f22a4af`, `3a33a10901e9ef89eace7834f9c7ce14f590e58bb1b50ec5bd44b4ef1ca5555a`, `1852120a84a328edd1995e633dfd2009867898a8e3f0b385e2490cf21c77a994`, `b3e853eee14fb7948c6907888ee07139085ba9af4231c30e97ff6236b86ca024`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
