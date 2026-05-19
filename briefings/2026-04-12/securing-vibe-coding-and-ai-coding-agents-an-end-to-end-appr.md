# [HIGH] Securing Vibe Coding and AI Coding Agents: An End-to-End Approach with StepSecurity

**Source:** StepSecurity
**Published:** 2026-04-12
**Article:** https://www.stepsecurity.io/blog/securing-vibe-coding-and-ai-coding-agents-an-end-to-end-approach-with-stepsecurity

## Threat Profile

Back to Blog Product Introducing StepSecurity Dev Machine Guard: Protecting Developer Machines from Supply Chain Attacks Modern supply chain attacks target developer machines and AI coding agents. Learn how StepSecurity Dev Machine Guard stops credential theft early Ashish Kurmi View LinkedIn January 13, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Developer machines hold your most sensitive credentials such as GitHub crede…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `metrics-trustwallet.com`
- **Domain (defanged):** `api.metrics-trustwallet.com`
- **SHA256:** `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **SHA256:** `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`
- **SHA256:** `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
- **SHA256:** `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`
- **SHA256:** `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- **SHA256:** `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`
- **SHA256:** `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- **SHA256:** `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1567** — Exfiltration Over Web Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1083** — File and Directory Discovery
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Shai-Hulud 2.0 C2 traffic to metrics-trustwallet.com / 138.124.70.40

`UC_292_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(DNS.answer) as answer values(DNS.src) as src from datamodel=Network_Resolution where (DNS.query="*metrics-trustwallet.com" OR DNS.query="metrics-trustwallet.com" OR DNS.query="api.metrics-trustwallet.com") by DNS.src DNS.query host | `drop_dm_object_name(DNS)` | appendpipe [| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Network_Traffic where (All_Traffic.dest="138.124.70.40" OR All_Traffic.dest_ip="138.124.70.40") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "metrics-trustwallet.com" or RemoteIP == "138.124.70.40"
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
  | where QueryName has "metrics-trustwallet.com"
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, QueryName, AdditionalFields
)
| order by Timestamp desc
```

### [LLM] Shai-Hulud 2.0 known-malicious payload SHA256 execution / file write

`UC_292_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as process values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777","dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c","4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | appendpipe [| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777","dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c","4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let ShaiHuludHashes = dynamic([
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
]);
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (ShaiHuludHashes) or InitiatingProcessSHA256 in (ShaiHuludHashes)
  | project Timestamp, Source="ProcessEvents", DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (ShaiHuludHashes)
  | project Timestamp, Source="FileEvents", DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
),
( DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (ShaiHuludHashes)
  | project Timestamp, Source="ImageLoad", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### [LLM] TruffleHog secret-scanner executed by npm/node/bun/yarn/pnpm parent

`UC_292_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdline values(Processes.process_path) as path from datamodel=Endpoint.Processes where (Processes.process_name="trufflehog*" OR Processes.process="*trufflehog*" OR Processes.process_path="*trufflehog*") AND (Processes.parent_process_name IN ("node.exe","node","npm.cmd","npm.exe","npm","npx.cmd","npx.exe","npx","bun.exe","bun","yarn.exe","yarn","yarn.cmd","pnpm.exe","pnpm","pnpm.cmd") OR Processes.parent_process="*node *" OR Processes.parent_process="*npm *" OR Processes.parent_process="*bun *") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let _pkg_mgr = dynamic(["node.exe","node","npm.cmd","npm.exe","npm","npx.cmd","npx.exe","npx","bun.exe","bun","yarn.exe","yarn","yarn.cmd","pnpm.exe","pnpm","pnpm.cmd"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName has "trufflehog"
   or ProcessCommandLine has "trufflehog"
   or FolderPath has "trufflehog"
| where InitiatingProcessFileName in~ (_pkg_mgr)
   or InitiatingProcessParentFileName in~ (_pkg_mgr)
   or InitiatingProcessCommandLine has_any ("node ", "npm ", "npx ", "bun ", "yarn ", "pnpm ")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] Shai-Hulud 2.0 signature file artifacts: setup_bun.js / bun_environment.js / shai-hulud-workflow.yml

`UC_292_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Filesystem.process_name) as written_by values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("setup_bun.js","bun_environment.js","shai-hulud-workflow.yml") OR Filesystem.file_path="*\\.github\\workflows\\shai-hulud-workflow.yml" OR Filesystem.file_path="*/.github/workflows/shai-hulud-workflow.yml") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("setup_bun.js","bun_environment.js","shai-hulud-workflow.yml")
   or FolderPath has @"\.github\workflows\shai-hulud-workflow.yml"
   or FolderPath has "/.github/workflows/shai-hulud-workflow.yml"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `metrics-trustwallet.com`, `api.metrics-trustwallet.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`, `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`, `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`, `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`, `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`, `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
