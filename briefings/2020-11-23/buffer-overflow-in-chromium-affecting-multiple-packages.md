# [CRIT] Buffer overflow in Chromium affecting multiple packages

**Source:** Snyk
**Published:** 2020-11-23
**Article:** https://snyk.io/blog/buffer-overflow-in-chromium-affecting-multiple-packages/

## Threat Profile

Snyk Blog In this article
Written by Alyssa Miller 
November 23, 2020
0 mins read Welcome to the Snyk Monthly Vulnerability Profile. In this series, Snyk looks back on the vulnerabilities discovered by or reported to our Security Research Team . We choose one noteworthy vulnerability from the past month and tell the story behind the discovery, research, and disclosure of the vulnerability. We highlight the researchers, developers, and users who are helping identify and remediate vulnerabilities …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-15999`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exposure hunt: CVE-2020-15999 FreeType overflow in Chromium/Electron/CefSharp software

`UC_3264_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, max(_time) as lastTime, values(Vulnerabilities.signature) as signature, values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2020-15999" by Vulnerabilities.dest, Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | sort - lastTime
```

**Defender KQL:**
```kql
let CveExposure = DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId == "CVE-2020-15999"
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, VulnerabilitySeverityLevel, Source="TVM-CVE";
let BundledInventory = DeviceTvmSoftwareInventory
| where Timestamp > ago(1d)
| where SoftwareName has_any ("electron","cefsharp","chromium","google chrome","chrome")
| extend RecommendedSecurityUpdate = "", VulnerabilitySeverityLevel = "", Source = "Inventory-Bundled"
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, VulnerabilitySeverityLevel, Source;
CveExposure
| union BundledInventory
| summarize Sources=make_set(Source), SoftwareVersions=make_set(SoftwareVersion), AnyRecommendedUpdate=any(RecommendedSecurityUpdate) by DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName
| order by SoftwareName asc, DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-15999`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
