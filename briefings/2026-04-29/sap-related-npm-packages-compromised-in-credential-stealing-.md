# [HIGH] SAP-Related npm Packages Compromised in Credential-Stealing Supply Chain Attack

**Source:** The Hacker News
**Published:** 2026-04-29
**Article:** https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html

## Threat Profile

Cybersecurity researchers are sounding the alarm about a new supply chain attack campaign targeting SAP-related npm Packages with credential-stealing malware. According to reports from Aikido Security, SafeDep, Socket, StepSecurity, and Google-owned Wiz, the campaign – calling itself the mini Shai-Hulud – has affected the following packages associated with SAP's JavaScript and cloud application

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — JavaScript
- **T1546.016** — Installer Packages
- **T1102.002** — Bidirectional Communication: Web Service
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service
- **T1105** — Ingress Tool Transfer
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### [LLM] Compromised SAP CAP / mbt npm package preinstall dropping setup.mjs (Mini Shai-Hulud)

`UC_4_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm-cli.js","yarn.exe","pnpm.exe","bun.exe","corepack.exe") OR Processes.parent_process IN ("*npm*install*","*yarn*add*","*pnpm*install*")) AND (Processes.process IN ("*setup.mjs*","*execution.js*") OR Processes.process IN ("*\\node_modules\\@cap-js\\sqlite*","*\\node_modules\\@cap-js\\postgres*","*\\node_modules\\@cap-js\\db-service*","*\\node_modules\\mbt\\*","*/node_modules/@cap-js/sqlite*","*/node_modules/@cap-js/postgres*","*/node_modules/@cap-js/db-service*","*/node_modules/mbt/*")) by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("setup.mjs","execution.js") AND (Filesystem.file_hash IN ("4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34","6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95","eb6eb4154b03ec73218727dc643d26f4e14dfda2438112926bb5daf37ae8bcdb","80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac","35baf8316645372eea40b91d48acb067")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let bad_hashes = dynamic(["4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34","6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95","eb6eb4154b03ec73218727dc643d26f4e14dfda2438112926bb5daf37ae8bcdb","80a3d2877813968ef847ae73b5eeeb70b9435254e74d7f07d8cf4057f0a710ac"]);
let bad_md5 = dynamic(["35baf8316645372eea40b91d48acb067"]);
let bad_paths = dynamic(["@cap-js/sqlite","@cap-js/postgres","@cap-js/db-service","/mbt/","\\mbt\\"]);
DeviceProcessEvents
| where (ProcessCommandLine has_any ("setup.mjs","execution.js") and InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","bun.exe","corepack.exe"))
   or (FolderPath has_any (bad_paths) and FileName in~ ("node.exe","bun.exe"))
   or SHA256 in (bad_hashes) or MD5 in (bad_md5)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| union (DeviceFileEvents | where (FileName in~ ("setup.mjs","execution.js") and FolderPath has_any (bad_paths)) or SHA256 in (bad_hashes) or MD5 in (bad_md5) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine)
```

### [LLM] Mini Shai-Hulud GitHub commit-search dead-drop C2 ('OhNoWhatsGoingOnWithGitHub')

`UC_4_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*OhNoWhatsGoingOnWithGitHub*" OR Web.url="*api.github.com/search/commits*OhNoWhatsGoingOnWithGitHub*" OR Web.http_user_agent="*Bun/1.3.13*") by Web.src Web.user Web.dest Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | where firstTime != ""
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("OhNoWhatsGoingOnWithGitHub", "api.github.com/search/commits")
| where RemoteUrl has "OhNoWhatsGoingOnWithGitHub"
   or (RemoteUrl has "api.github.com/search/commits" and InitiatingProcessFileName in~ ("bun.exe","node.exe"))
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| union (
DeviceEvents
| where ActionType == "BrowserLaunchedToOpenUrl" or ActionType == "NetworkConnectionEvents"
| where AdditionalFields has "OhNoWhatsGoingOnWithGitHub"
)
```

### [LLM] Bun v1.3.13 runtime fetched from npm/node install context (Mini Shai-Hulud dropper)

`UC_4_3` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*github.com/oven-sh/bun/releases/download/bun-v1.3.13*" by Web.src Web.user Web.url Web.http_user_agent Web.dest | `drop_dm_object_name(Web)` | join type=outer src [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="bun.exe" AND (Processes.process IN ("*execution.js*","*\\.claude\\*","*\\.vscode\\setup.mjs*")) by Processes.dest Processes.user Processes.parent_process Processes.process | rename Processes.dest as src | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let bun_dl =
DeviceNetworkEvents
| where RemoteUrl has "github.com/oven-sh/bun/releases/download/bun-v1.3.13"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","curl.exe","wget.exe","powershell.exe","pwsh.exe","cmd.exe")
| project NetTime=Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;
let bun_exec =
DeviceProcessEvents
| where FileName =~ "bun.exe" or ProcessCommandLine matches regex @"(?i)\bbun\b.*(execution\.js|\.claude\\|\.vscode\\setup\.mjs)"
| where ProcessCommandLine has_any ("execution.js",".claude\\",".vscode\\setup.mjs")
| project ExecTime=Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath;
bun_dl
| join kind=inner (bun_exec) on DeviceName
| where datetime_diff('minute', ExecTime, NetTime) between (-30 .. 30)
| project NetTime, ExecTime, DeviceName, AccountName, RemoteUrl, ProcessCommandLine, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
