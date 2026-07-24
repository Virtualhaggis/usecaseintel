# [CRIT] Preventing malicious packages and supply chain attacks with Snyk

**Source:** Snyk
**Published:** 2021-08-31
**Article:** https://snyk.io/blog/preventing-malicious-packages-and-supply-chain-attacks-with-snyk/

## Threat Profile

Snyk Blog In this article
Written by Daniel Berman 
August 31, 2021
0 mins read Open source packages play a critical role in modern software development, fueling the rapid pace of development we’re witnessing all around us. For a developer looking to introduce new functionality into his application, it simply doesn’t make sense to reinvent the wheel. Why not simply install a package that someone else has already invested the time in building and that provides the exact same functionality?
But th…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Known-malicious npm packages flatmap-stream / lyft-dataset-sdk landing on host

`UC_3088_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| union 
  [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules*flatmap-stream*" OR Filesystem.file_path="*node_modules*lyft-dataset-sdk*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name 
   | `drop_dm_object_name(Filesystem)` | eval signal="node_modules_write"] 
  [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe") OR Processes.parent_process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe")) AND (Processes.process="*flatmap-stream*" OR Processes.process="*lyft-dataset-sdk*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name 
   | `drop_dm_object_name(Processes)` | eval signal="install_cmdline"] 
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` 
| sort - lastTime
```

**Defender KQL:**
```kql
union
(
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","npm","node","yarn","pnpm","npx")
      or InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe","npm","node","yarn","pnpm","npx"))
| where ProcessCommandLine contains "flatmap-stream" or ProcessCommandLine contains "lyft-dataset-sdk"
| project Timestamp, DeviceName, AccountName, Signal="install_cmdline", Path=FolderPath, CmdLine=ProcessCommandLine, ParentCmd=InitiatingProcessCommandLine
),
(
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath contains @"node_modules\flatmap-stream" or FolderPath contains "node_modules/flatmap-stream" or FolderPath contains @"node_modules\lyft-dataset-sdk" or FolderPath contains "node_modules/lyft-dataset-sdk"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Signal="node_modules_write", Path=FolderPath, CmdLine=InitiatingProcessCommandLine, ParentCmd=InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

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

Severity classified as **CRIT** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
