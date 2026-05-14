# [CRIT] [GHSA / CRITICAL] GHSA-54pg-9963-v8vg: Compromised version of intercom-client published to npm

**Source:** GitHub Security Advisories
**Published:** 2026-05-07
**Article:** https://github.com/advisories/GHSA-54pg-9963-v8vg

## Threat Profile

Compromised tag of intercom-php published via GitHub

### Impact

On April 30, 2026, a malicious commit was pushed to the intercom/intercom-php repository and tagged as version 5.0.2, using a compromised service account (github-management-service). This occurred as part of the same supply chain attack that affected intercom-client on npm.

The malicious version contained a Composer plugin that acted as a dropper, downloading the Bun JavaScript runtime (version 1.3.13) and executing an obfuscated…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1546.016** — Event Triggered Execution: Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud C2 beacon — zero.masscan.cloud /v1/telemetry exfiltration endpoint

`UC_134_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents from datamodel=Web.Web where (Web.dest="zero.masscan.cloud" OR Web.dest="*.masscan.cloud" OR Web.url="*zero.masscan.cloud*" OR Web.url="*masscan.cloud/v1/telemetry*") by Web.src Web.dest Web.user Web.app | `drop_dm_object_name(Web)` | appendpipe [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Resolution.query) as queries from datamodel=Network_Resolution.DNS where (Network_Resolution.query="zero.masscan.cloud" OR Network_Resolution.query="*.masscan.cloud") by Network_Resolution.src Network_Resolution.dest | `drop_dm_object_name(Network_Resolution)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Mini Shai-Hulud C2 endpoint observed in intercom-php 5.0.2 supply chain compromise
let C2Host = dynamic(["zero.masscan.cloud","masscan.cloud"]);
let C2Path = "/v1/telemetry";
union isfuzzy=true
  ( DeviceNetworkEvents
      | where Timestamp > ago(30d)
      | where RemoteUrl has_any (C2Host) or RemoteUrl has "masscan.cloud"
      | project Timestamp, DeviceName, DeviceId, ActionType,
                RemoteIP, RemotePort, RemoteUrl,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                InitiatingProcessAccountName, InitiatingProcessFolderPath ),
  ( DeviceEvents
      | where Timestamp > ago(30d)
      | where ActionType == "DnsQueryResponse"
      | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
      | where QueryName has "masscan.cloud"
      | project Timestamp, DeviceName, DeviceId, ActionType,
                RemoteUrl = QueryName,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                InitiatingProcessAccountName, InitiatingProcessFolderPath = "" )
| order by Timestamp asc
```

### [LLM] Composer post-install/post-update hook spawns Bun runtime or setup-intercom.sh dropper

`UC_134_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_path) as paths from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php","php.exe","composer","composer.phar","composer.exe") OR Processes.parent_process="*composer*install*" OR Processes.parent_process="*composer*update*" OR Processes.parent_process="*post-install-cmd*" OR Processes.parent_process="*post-update-cmd*") AND (Processes.process_name IN ("bun","bun.exe") OR Processes.process="*setup-intercom.sh*" OR Processes.process="*router_runtime.js*" OR Processes.process="*bun-v1.3.13*" OR Processes.process="*oven-sh/bun*" OR Processes.process="*Running Intercom setup script*" OR Processes.process="*Intercom\\ComposerPlugin*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Composer post-install/post-update dropper from intercom-php 5.0.2 (Mini Shai-Hulud)
let ComposerParents = dynamic(["php.exe","php","composer.exe","composer","composer.phar"]);
let DropperStrings = dynamic(["setup-intercom.sh","router_runtime.js","bun-v1.3.13","oven-sh/bun","Running Intercom setup script","Intercom\\ComposerPlugin","post-install-cmd","post-update-cmd"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where (InitiatingProcessFileName in~ (ComposerParents))
     or (InitiatingProcessCommandLine has_any ("composer install","composer update","composer.phar install","composer.phar update"))
| where FileName in~ ("bun","bun.exe","sh","bash","curl","wget","powershell.exe","pwsh")
      or ProcessCommandLine has_any (DropperStrings)
      or FolderPath has_any (@"/.claude/",@"/.vscode/",@"\.claude\",@"\.vscode\")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildName = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud payload artefact on disk — router_runtime.js / setup-intercom.sh / known SHA256

`UC_134_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.file_hash) as hashes values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("setup-intercom.sh","router_runtime.js","setup.mjs") OR Filesystem.file_path="*\\.claude\\router_runtime.js" OR Filesystem.file_path="*/.claude/router_runtime.js" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*/.vscode/setup.mjs" OR Filesystem.file_path="*\\results\\results-*.json" OR Filesystem.file_path="*/results/results-*.json" OR Filesystem.file_hash IN ("832a976d1a8d54e296e8479aedbd89fa24baa02b8408a78bf06d4d03340881bd","50212a875643520353df158196b9b3be4595094125ad8d2d2c48bfd9cb04ce1f","66664a49edbcee0ed0d8365839707916e92d3aa06e7f26f33c9dcc58e5fc1ef3")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Mini Shai-Hulud / intercom-php payload artefacts on disk
let KnownHashes = dynamic([
    "832a976d1a8d54e296e8479aedbd89fa24baa02b8408a78bf06d4d03340881bd",  // setup-intercom.sh
    "50212a875643520353df158196b9b3be4595094125ad8d2d2c48bfd9cb04ce1f",  // router_runtime.js
    "66664a49edbcee0ed0d8365839707916e92d3aa06e7f26f33c9dcc58e5fc1ef3"   // intercom-intercom-php-5.0.2.zip
]);
let KnownNames = dynamic(["setup-intercom.sh","router_runtime.js"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where SHA256 in (KnownHashes)
    or FileName in~ (KnownNames)
    or FolderPath has_any (@"\.claude\", @"/.claude/", @"\.vscode\", @"/.vscode/")
      and FileName in~ ("router_runtime.js","setup.mjs")
    or (FolderPath has_any (@"\results\", @"/results/") and FileName startswith "results-" and FileName endswith ".json")
| project Timestamp, DeviceName, ActionType,
          FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

Severity classified as **CRIT** based on: 5 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
