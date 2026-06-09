# [HIGH] Microsoft Patch Tuesday June 2026 – 198 Vulnerabilities Fixed, Including 3 0-days

**Source:** Cyber Security News
**Published:** 2026-06-09
**Article:** https://cybersecuritynews.com/microsoft-patch-tuesday-june-2026/

## Threat Profile

Microsoft has released its June 2026 Patch Tuesday security updates, addressing a hefty 198 vulnerabilities across its product ecosystem. The June rollout, published on June 9, 2026, stands out not only for its volume but also for the inclusion of three zero-day vulnerabilities that were actively exploited or publicly known before a fix was available. [&#8230;] The post Microsoft Patch Tuesday June 2026 – 198 Vulnerabilities Fixed, Including 3 0-days appeared first on Cyber Security News .

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-50507`
- **CVE:** `CVE-2026-49160`
- **CVE:** `CVE-2026-45586`
- **CVE:** `CVE-2026-44801`
- **CVE:** `CVE-2026-44799`
- **CVE:** `CVE-2026-42992`
- **CVE:** `CVE-2026-42985`
- **CVE:** `CVE-2026-47652`
- **CVE:** `CVE-2026-45641`
- **CVE:** `CVE-2026-45607`
- **CVE:** `CVE-2026-47291`
- **CVE:** `CVE-2026-47288`
- **CVE:** `CVE-2026-45648`
- **CVE:** `CVE-2026-32193`
- **CVE:** `CVE-2026-26142`
- **CVE:** `CVE-2026-45458`
- **CVE:** `CVE-2026-45456`
- **CVE:** `CVE-2026-45474`
- **CVE:** `CVE-2026-45472`
- **CVE:** `CVE-2026-48583`
- **CVE:** `CVE-2026-45653`
- **CVE:** `CVE-2026-44810`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-50507`, `CVE-2026-49160`, `CVE-2026-45586`, `CVE-2026-44801`, `CVE-2026-44799`, `CVE-2026-42992`, `CVE-2026-42985`, `CVE-2026-47652` _(+14 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
