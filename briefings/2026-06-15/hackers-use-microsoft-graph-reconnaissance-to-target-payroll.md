# [MED] Hackers Use Microsoft Graph Reconnaissance to Target Payroll and HR Employees

**Source:** Cyber Security News
**Published:** 2026-06-15
**Article:** https://cybersecuritynews.com/hackers-use-microsoft-graph-reconnaissance/

## Threat Profile

Hackers are using Microsoft&#8217;s own cloud tools to quietly hunt down payroll and HR staff inside corporate networks, then reroute employee salaries to accounts they control. Security teams are racing to respond as the campaign continues to spread across industries and borders. The attack method is deceptively clean. Instead of planting malware or exploiting software [&#8230;] The post Hackers Use Microsoft Graph Reconnaissance to Target Payroll and HR Employees appeared first on Cyber Securi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-27152`
- **IPv4 (defanged):** `216.247.226.32`
- **IPv4 (defanged):** `24.53.42.79`
- **IPv4 (defanged):** `99.239.33.130`
- **IPv4 (defanged):** `75.152.86.244`
- **IPv4 (defanged):** `144.172.190.50`
- **IPv4 (defanged):** `72.143.216.88`
- **IPv4 (defanged):** `173.178.178.139`
- **IPv4 (defanged):** `216.16.184.145`
- **IPv4 (defanged):** `108.208.40.144`
- **IPv4 (defanged):** `70.83.127.83`
- **IPv4 (defanged):** `24.202.0.56`
- **IPv4 (defanged):** `72.45.107.194`
- **IPv4 (defanged):** `47.55.96.251`
- **IPv4 (defanged):** `70.24.235.36`
- **IPv4 (defanged):** `199.126.64.61`
- **IPv4 (defanged):** `70.67.169.118`
- **IPv4 (defanged):** `99.244.137.184`
- **Domain (defanged):** `bluegraintours.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-27152`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `216.247.226.32`, `24.53.42.79`, `99.239.33.130`, `75.152.86.244`, `144.172.190.50`, `72.143.216.88`, `173.178.178.139`, `216.16.184.145` _(+10 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
