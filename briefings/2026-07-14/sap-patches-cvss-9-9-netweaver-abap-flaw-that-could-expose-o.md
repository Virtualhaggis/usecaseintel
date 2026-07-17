# [CRIT] SAP Patches CVSS 9.9 NetWeaver ABAP Flaw That Could Expose or Modify Data

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/sap-patches-cvss-99-netweaver-abap-flaw.html

## Threat Profile

SAP Patches CVSS 9.9 NetWeaver ABAP Flaw That Could Expose or Modify Data 
 Ravie Lakshmanan  Jul 14, 2026 Enterprise Security / Vulnerability 
SAP has rolled out updates to address multiple vulnerabilities as part of its July 2026 security updates, including a critical flaw in SAP NetWeaver Application Server ABAP.
The vulnerability in question is CVE-2026-44747 (CVSS score: 9.9), an out-of-bounds write flaw that allows an authenticated attacker to leverage logical errors in memory management…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-44747`
- **CVE:** `CVE-2026-27690`
- **CVE:** `CVE-2026-44761`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1078.001** — Valid Accounts: Default Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SAP July 2026 Patch Day exposure hunt — critical NetWeaver/Approuter/Commerce Cloud CVEs (internet-facing first)

`UC_75_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2026-44747", "CVE-2026-27690", "CVE-2026-44761")
| where SoftwareVendor has "sap"
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId
  ) on DeviceId
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate,
          IsInternetFacing, PublicIP
| sort by IsInternetFacing desc, CveId asc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-44747`, `CVE-2026-27690`, `CVE-2026-44761`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
