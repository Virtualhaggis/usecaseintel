# [HIGH] How and when to use Docker labels / OCI container annotations

**Source:** Snyk
**Published:** 2021-11-03
**Article:** https://snyk.io/blog/how-and-when-to-use-docker-labels-oci-container-annotations/

## Threat Profile

Snyk Blog In this article
Written by Eric Smalling 
November 3, 2021
0 mins read Most container images are built using Dockerfiles which contain combinations of instructions like FROM , RUN , COPY , ENTRYPOINT , etc. to build the layers of an OCI-compliant image. One instruction that is used surprisingly rarely, though, is LABEL . In this post, we’ll dig into labels ("annotations" in the OCI Image Specification ) what they are, some standardized uses as well as some practices you can use to enha…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `c958ffc87c2bd5af500d24eff1ccb3ee21992a5cbcb429fafcc651aa182b66ba`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c958ffc87c2bd5af500d24eff1ccb3ee21992a5cbcb429fafcc651aa182b66ba`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
