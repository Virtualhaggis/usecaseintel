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

### Vulnerable DotVVM version in software inventory (<4.2.11 / <4.3.15 / <5.0.0-preview09)

`UC_56_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
// GHSA-c8qj-jx8j-fg2w: DotVVM AuthorizeActionFilter does nothing. Fixed in 4.2.11, 4.3.15, 5.0.0-preview09.
DeviceTvmSoftwareInventory
| where SoftwareName has "dotvvm" or SoftwareVendor has "dotvvm"
| extend BaseVer = tostring(split(SoftwareVersion, "-")[0])
| extend PreviewNum = toint(extract(@"preview0*(\d+)", 1, tolower(SoftwareVersion)))
| where (parse_version(BaseVer) < parse_version("4.2.11"))                                              // entire <4.2.11 lineage
     or (parse_version(BaseVer) >= parse_version("4.3.0") and parse_version(BaseVer) < parse_version("4.3.15")) // 4.3.0-preview01 .. 4.3.15
     or (BaseVer == "5.0.0" and isnotnull(PreviewNum) and PreviewNum < 9)                                  // 5.0.0-preview01 .. preview09
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion
| sort by DeviceName asc
```

### DotVVM framework assembly deployed/loaded on endpoints — exposure hunt for GHSA-c8qj-jx8j-fg2w

`UC_56_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="DotVVM*.dll" by Filesystem.dest Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
// Identify hosts running DotVVM by the framework assembly loaded into the web host process.
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName has "dotvvm" and FileName endswith ".dll"
| where InitiatingProcessFileName in~ ("w3wp.exe","dotnet.exe","iisexpress.exe")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Modules=make_set(FileName,20), Paths=make_set(FolderPath,20) by DeviceName, InitiatingProcessFileName
| sort by LastSeen desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
