# [MED] Harden-Runner Flags Anomalous Outbound Call, Leading to Docker Documentation Update

**Source:** StepSecurity
**Published:** 2025-07-08
**Article:** https://www.stepsecurity.io/blog/harden-runner-flags-anomalous-outbound-call-leading-to-docker-documentation-update

## Threat Profile

Back to Blog Product Harden-Runner Flags Anomalous Outbound Call, Leading to Docker Documentation Update Harden-Runner detected an unexpected outbound call from Docker across multiple customer environments. Surprisingly, it wasn’t listed in Docker’s allow list, and no EDR tool flagged it. Here’s how we identified it, reported it, and got it added to Docker’s documentation. Varun Sharma View LinkedIn February 6, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
T…

## Indicators of Compromise (high-fidelity only)

- **MD5:** `6aa30f8b08e16409b46e0173d6de2f56`

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
  - file hash IOC(s): `6aa30f8b08e16409b46e0173d6de2f56`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
