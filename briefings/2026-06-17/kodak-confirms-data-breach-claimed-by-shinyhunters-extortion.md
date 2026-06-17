# [HIGH] Kodak confirms data breach claimed by ShinyHunters extortion gang

**Source:** BleepingComputer
**Published:** 2026-06-17
**Article:** https://www.bleepingcomputer.com/news/security/kodak-confirms-data-breach-claimed-by-shinyhunters-extortion-gang/

## Threat Profile

Kodak confirms data breach claimed by ShinyHunters extortion gang 
By Sergiu Gatlan 
June 17, 2026
03:07 AM
0 
Kodak has confirmed that it's working with external cybersecurity experts to investigate a security breach after hackers gained access to some of the company's data.
Founded in 1880 as the Eastman Kodak Company and headquartered in Rochester, New York, Kodak has 79,000 worldwide patents and provides commercial print, advanced materials, and chemical products.
A company spokesperson told…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35273`
- **IPv4 (defanged):** `142.11.200.186`
- **IPv4 (defanged):** `142.11.200.187`
- **IPv4 (defanged):** `142.11.200.188`
- **IPv4 (defanged):** `142.11.200.189`
- **IPv4 (defanged):** `142.11.200.190`
- **IPv4 (defanged):** `176.120.22.24`
- **Domain (defanged):** `azurenetfiles.net`
- **SHA256:** `2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35`
- **SHA256:** `f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc`
- **SHA256:** `d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f`
- **SHA256:** `c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f`
- **SHA256:** `68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35273`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.200.186`, `142.11.200.187`, `142.11.200.188`, `142.11.200.189`, `142.11.200.190`, `176.120.22.24`, `azurenetfiles.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2ab684d93c1553fad87041b4dea97188a97e78589deee2a7bacff905564f3a35`, `f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc`, `d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f`, `c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f`, `68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
