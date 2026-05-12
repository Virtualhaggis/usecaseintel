# [HIGH] [GHSA / HIGH] GHSA-w94c-4vhp-22gx: @vitejs/plugin-rsc has a Denial of Service Vulnerability in React Server Components

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories/GHSA-w94c-4vhp-22gx

## Threat Profile

Facebook React has a Denial of Service Vulnerability in React Server Components

## Impact

A denial of service vulnerability could be triggered by sending specially crafted HTTP requests to server function endpoints, this could lead to out-of-memory exceptions or excessive CPU usage.

We recommend updating immediately.

The vulnerability exists in versions 19.0.0 through 19.0.5, 19.1.0 through 19.1.6, and 19.2.0 through 19.2.5 of:

[react-server-dom-webpack](https://www.npmjs.com/package/react-…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-23870`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vulnerable react-server-dom-* RSC package in software inventory (CVE-2026-23870)

`UC_81_1` · phase: **recon** · confidence: **High**

**Defender KQL:**
```kql
// CVE-2026-23870 — vulnerable react-server-dom-* packages
let _vulnerable_packages = dynamic(["react-server-dom-webpack","react-server-dom-parcel","react-server-dom-turbopack"]);
let _fixed_versions = dynamic(["19.0.6","19.1.7","19.2.6"]);
DeviceTvmSoftwareInventory
| where SoftwareVendor has "react" or SoftwareName has_any (_vulnerable_packages)
| where SoftwareName has_any (_vulnerable_packages)
| extend Major = toint(extract(@"^(\d+)\.",1,SoftwareVersion)),
         Minor = toint(extract(@"^\d+\.(\d+)\.",1,SoftwareVersion)),
         Patch = toint(extract(@"^\d+\.\d+\.(\d+)",1,SoftwareVersion))
| where Major == 19
      and ((Minor == 0 and Patch between (0 .. 5))
        or (Minor == 1 and Patch between (0 .. 6))
        or (Minor == 2 and Patch between (0 .. 5)))
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp,*) by DeviceId
     | project DeviceId, IsInternetFacing) on DeviceId
| project Timestamp, DeviceName, IsInternetFacing, SoftwareName, SoftwareVersion, EndOfSupportStatus
| order by IsInternetFacing desc, DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-23870`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
