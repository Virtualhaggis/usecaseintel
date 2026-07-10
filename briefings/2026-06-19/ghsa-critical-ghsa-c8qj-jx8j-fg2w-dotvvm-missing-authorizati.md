# [CRIT] [GHSA / CRITICAL] GHSA-c8qj-jx8j-fg2w: DotVVM: Missing authorization in AuthorizeActionFilter

**Source:** GitHub Security Advisories
**Published:** 2026-06-19
**Article:** https://github.com/advisories/GHSA-c8qj-jx8j-fg2w

## Threat Profile

DotVVM: Missing authorization in AuthorizeActionFilter

### Impact

All users of the `AuthorizeActionFilter` class are affected. The `AuthorizeActionFilter` simply does nothing, no “hacking” is needed to bypass the filter.

### Patches

DotVVM 4.3.15, 4.2.11 and 5.0.0-preview09 fix this.

### Workarounds

As a workaround, you can use the `AuthorizeAttribute` instead. It implements the same interfaces (correctly). Note that is it deprecated for unrelated reasons, feel free to suppress the warning…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Anonymous HTTP 200 to DotVVM endpoints (AuthorizeActionFilter bypass exploitation)

`UC_235_0` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Web.uri_path) as uri_path, values(Web.http_method) as http_method, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.status=200 (Web.url="*.dothtml*" OR Web.url="*dotvvm*" OR Web.uri_path="*.dothtml*" OR Web.uri_path="*dotvvm*") (Web.user="-" OR Web.user="" OR Web.user="anonymous") by Web.src, Web.dest, Web.user, Web.status | `drop_dm_object_name(Web)` | where count > 0 | convert ctime(firstTime) ctime(lastTime) | sort - count
```

### Vulnerable DotVVM framework version present on host (GHSA-c8qj-jx8j-fg2w)

`UC_235_1` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "dotvvm" or SoftwareVendor has "dotvvm" or SoftwareVendor has "riganti"
| extend VerCore = extract(@"^(\d+\.\d+\.\d+)", 1, SoftwareVersion)
| where isnotempty(VerCore)
| extend V = parse_version(VerCore)
| extend PreviewNum = toint(extract(@"preview0*(\d+)", 1, SoftwareVersion))
| where (V < parse_version("4.2.11"))                                                  // whole 4.2.x and earlier line
     or (V >= parse_version("4.3.0") and V < parse_version("4.3.15"))                   // 4.3.0-preview01..4.3.14
     or (V == parse_version("5.0.0") and SoftwareVersion has "preview" and PreviewNum < 9) // 5.0.0-preview01..08
| project Timestamp, DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| sort by DeviceName asc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
