# [CRIT] Zimbra urges customers to patch critical web client XSS flaw

**Source:** BleepingComputer
**Published:** 2026-07-10
**Article:** https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/

## Threat Profile

Zimbra urges customers to patch critical web client XSS flaw 
By Sergiu Gatlan 
July 10, 2026
07:47 AM
0 
The Zimbra security team urged customers to patch a critical vulnerability affecting the Classic Web Client used to access the Zimbra Collaboration suite.
Zimbra is a very popular email and collaboration software suite used by hundreds of millions of people, including thousands of businesses and hundreds of government agencies worldwide. Also known as the Classic UI, this Ajax-based webmail …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-66376`
- **CVE:** `CVE-2025-48700`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1114.002** — Remote Email Collection
- **T1539** — Steal Web Session Cookie

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-facing Zimbra Collaboration exposed to Classic Web Client XSS (10.1.19 / CVE-2025-66376 / CVE-2025-48700)

`UC_36_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2025-66376","CVE-2025-48700") OR Vulnerabilities.signature="*Zimbra*" OR Vulnerabilities.signature="*Collaboration*") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.category | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where Timestamp > ago(1d)
| where SoftwareVendor has "zimbra" or SoftwareName has "zimbra"
| join kind=leftouter (DeviceInfo | where Timestamp > ago(7d) | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId) on DeviceId
| join kind=leftouter (DeviceTvmSoftwareVulnerabilities | where CveId in ("CVE-2025-66376","CVE-2025-48700") | summarize KnownExploitedCVEs=make_set(CveId) by DeviceId) on DeviceId
| extend PatchedToFix = SoftwareVersion has "10.1.19" or SoftwareVersion has "10.1.20"
| where PatchedToFix == false or array_length(KnownExploitedCVEs) > 0
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, IsInternetFacing, PublicIP, KnownExploitedCVEs, EndOfSupportStatus
| order by IsInternetFacing desc, SoftwareVersion asc
```

### Zimbra webmail mailbox mass-scrape via burst of /service/soap requests (GhostMail post-XSS collection)

`UC_36_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count values(Web.http_method) as methods from datamodel=Web where Web.url="*/service/soap*" by Web.src Web.dest Web.site _time span=1h | `drop_dm_object_name(Web)` | where count > 500 | sort - count
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-66376`, `CVE-2025-48700`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
