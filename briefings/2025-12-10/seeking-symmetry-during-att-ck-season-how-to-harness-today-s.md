# [HIGH] Seeking symmetry during ATT&CK® season: How to harness today’s diverse analyst and tester landscape to paint a security masterpiece

**Source:** ESET WeLiveSecurity
**Published:** 2025-12-10
**Article:** https://www.welivesecurity.com/en/business-security/seeking-symmetry-attck-season-harness-todays-diverse-analyst-tester-landscape-paint-security-masterpiece/

## Threat Profile

Seeking symmetry during ATT&CK® season: How to harness today’s diverse analyst and tester landscape to paint a security masterpiece 
Business Security
Seeking symmetry during ATT&CK® season: How to harness today’s diverse analyst and tester landscape to paint a security masterpiece Interpreting the vast cybersecurity vendor landscape through the lens of industry analysts and testing authorities can immensely enhance your cyber-resilience.
Márk Szabó 
James Shepperd 
Ben Tudor 
10 Dec 2025 
 •  
…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain

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


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
