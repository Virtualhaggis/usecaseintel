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
- **T1212** — Exploitation for Credential Access

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable DotVVM NuGet package deployed (GHSA-c8qj-jx8j-fg2w)

`UC_16_0` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.signature="DotVVM" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.file_version | `drop_dm_object_name(Vulnerabilities)` | rex field=file_version "^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<pre>[\w\.-]+))?$" | eval major=tonumber(major), minor=tonumber(minor), patch=tonumber(patch) | eval vulnerable=case( major==4 AND minor==2 AND patch<11, "4.2.x < 4.2.11", major==4 AND minor==3 AND ((patch<15) OR (patch==0 AND isnotnull(pre) AND NOT match(pre,"^preview01"))), "4.3.x < 4.3.15", major==5 AND minor==0 AND patch==0 AND isnotnull(pre) AND match(pre,"^preview0[1-8]"), "5.0.0-preview01..preview08", 1==1, null()) | where isnotnull(vulnerable) | table dest signature file_version vulnerable
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "dotvvm" or SoftwareVendor has "riganti"
| extend Parts = split(SoftwareVersion, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1])
| extend PatchRaw = tostring(Parts[2])
| extend Patch = toint(extract(@"^(\d+)", 1, PatchRaw))
| extend PreRelease = extract(@"-(.+)$", 1, SoftwareVersion)
| extend PreviewNum = toint(extract(@"preview0?(\d+)", 1, tolower(PreRelease)))
| extend Vulnerable = case(
    Major == 4 and Minor == 2 and Patch < 11, "4.2.x < 4.2.11",
    Major == 4 and Minor == 3 and Patch < 15 and isempty(PreRelease), "4.3.x < 4.3.15",
    Major == 4 and Minor == 3 and Patch == 0 and isnotempty(PreRelease) and PreviewNum > 1, "4.3.0-preview > 01",
    Major == 5 and Minor == 0 and Patch == 0 and PreviewNum between (1 .. 8), "5.0.0-preview01..preview08",
    "")
| where isnotempty(Vulnerable)
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, MachineGroup) by DeviceId) on DeviceId
| project Timestamp, DeviceName, DeviceId, SoftwareName, SoftwareVersion, Vulnerable, IsInternetFacing, MachineGroup
| order by IsInternetFacing desc, Timestamp desc
```

### DotVVM framework assembly load on production host (exposure surface)

`UC_16_1` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName in~ ("DotVVM.Framework.dll", "DotVVM.Core.dll", "DotVVM.AspNetCore.dll", "DotVVM.Owin.dll")
| where InitiatingProcessFileName in~ ("w3wp.exe", "iisexpress.exe", "dotnet.exe", "DotVVM.Compiler.exe")
| summarize FirstLoad = min(Timestamp), LastLoad = max(Timestamp), LoadCount = count(), Workers = make_set(InitiatingProcessFileName, 16), AssembliesLoaded = make_set(FileName, 8)
  by DeviceId, DeviceName
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, MachineGroup) by DeviceId) on DeviceId
| project FirstLoad, LastLoad, DeviceName, IsInternetFacing, MachineGroup, Workers, AssembliesLoaded, LoadCount
| order by IsInternetFacing desc, LastLoad desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
