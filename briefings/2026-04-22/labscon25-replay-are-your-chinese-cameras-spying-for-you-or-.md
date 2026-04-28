# [MED] LABScon25 Replay | Are Your Chinese Cameras Spying For You Or On You?

**Source:** SentinelLabs
**Published:** 2026-04-22
**Article:** https://www.sentinelone.com/labs/labscon25-replay-are-your-chinese-cameras-spying-for-you-or-on-you/

## Threat Profile

LABScon 
LABScon25 Replay | Are Your Chinese Cameras Spying For You Or On You? 
LABScon 
/
April 22, 2026 
In this LABScon 25 presentation, Marc Rogers and Silas Cutler explore the complex, “shadow” supply chain of ultra-cheap Chinese smart home devices, specifically focusing on video doorbells and security cameras widely sold on mainstream online shopping platforms under various rotating brand names like Eken and Tuck.
Marc, who assisted the FCC Enforcement Bureau in its investigations, and Sil…

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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
