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
- **T1071.004** — Application Layer Protocol: DNS
- **T1567** — Exfiltration Over Web Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1204.003** — User Execution: Malicious Image
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Trust Wallet Shai-Hulud C2 beacon to metrics-trustwallet.com

`UC_295_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("metrics-trustwallet.com","api.metrics-trustwallet.com","*.metrics-trustwallet.com") OR All_Traffic.dest_ip="138.124.70.40") by All_Traffic.src host_dest=All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=t count from datamodel=Web.Web where (Web.url="*metrics-trustwallet.com*" OR Web.dest="138.124.70.40") by Web.src Web.url Web.user | `drop_dm_object_name(Web)` ] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// Trust Wallet Shai-Hulud C2 — metrics-trustwallet.com / 138.124.70.40
let c2_domains = dynamic(["metrics-trustwallet.com","api.metrics-trustwallet.com"]);
let c2_ips = dynamic(["138.124.70.40"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (c2_domains)
       or RemoteIP in (c2_ips)
    | project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, ReportId, Source = "DeviceNetworkEvents" ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName has_any (c2_domains)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              RemoteUrl = QueryName, RemoteIP = "", RemotePort = int(null),
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, ReportId, Source = "DeviceEvents-DNS" )
| order by Timestamp desc
```

### [LLM] Shai-Hulud campaign malware SHA256 present on developer endpoint

`UC_295_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777","dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c","4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777","dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c","4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` ] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// Shai-Hulud / Trust Wallet npm worm — known-malicious SHA256 sweep
let ShaiHulud_SHA256 = dynamic([
  "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
  "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
  "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
  "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
  "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
  "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
  "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
  "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
]);
union isfuzzy=true
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (ShaiHulud_SHA256) or InitiatingProcessSHA256 in (ShaiHulud_SHA256)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256,
              ProcessCommandLine, Source = "DeviceProcessEvents" ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (ShaiHulud_SHA256)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessSHA256 = "", ProcessCommandLine = "", Source = "DeviceFileEvents" ),
  ( DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (ShaiHulud_SHA256)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessSHA256 = "", ProcessCommandLine = "", Source = "DeviceImageLoadEvents" )
| order by Timestamp desc
```

### [LLM] npm/node postinstall harvests developer credentials via trufflehog or direct secret-file read

`UC_295_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as process_name values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","node","npm.cmd","npm","yarn.cmd","yarn","pnpm.cmd","pnpm","npx.cmd","npx") AND ( Processes.process_name IN ("trufflehog","trufflehog.exe","trufflehog3") OR Processes.process IN ("*\\.ssh\\id_rsa*","*/.ssh/id_rsa*","*\\.aws\\credentials*","*/.aws/credentials*","*\\.npmrc*","*/.npmrc*","*\\.git-credentials*","*/.git-credentials*","*\\hosts.yml*","*/hosts.yml*") OR Processes.process IN ("*GITHUB_TOKEN*","*GH_TOKEN*","*NPM_TOKEN*","*AWS_SECRET*","*printenv*","*env | grep*","*Get-ChildItem Env:*") ) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// Shai-Hulud-style npm postinstall credential harvest — child of node/npm/yarn reading developer secrets or running trufflehog
let pkg_parents = dynamic(["node.exe","node","npm.cmd","npm","npm-cli.js","yarn.cmd","yarn","pnpm.cmd","pnpm","npx.cmd","npx","bun.exe","bun"]);
let trufflehog = dynamic(["trufflehog.exe","trufflehog","trufflehog3","gitleaks.exe","gitleaks"]);
let secret_path_tokens = dynamic([@"\.ssh\id_rsa","/.ssh/id_rsa",@"\.ssh\id_ed25519","/.ssh/id_ed25519",@"\.aws\credentials","/.aws/credentials",@"\.npmrc","/.npmrc",@"\.git-credentials","/.git-credentials",@"\gh\hosts.yml","/gh/hosts.yml",@"\Google\Chrome\User Data\Default\Login Data",@"\AppData\Roaming\npm\etc\npmrc"]);
let env_tokens = dynamic(["GITHUB_TOKEN","GH_TOKEN","NPM_TOKEN","NODE_AUTH_TOKEN","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN","OPENAI_API_KEY","CLOUDFLARE_API_TOKEN"]);
let env_dumpers = dynamic(["printenv","env | grep","Get-ChildItem Env:","Get-ChildItem env:","$env:","set | findstr"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ (pkg_parents)
   or InitiatingProcessParentFileName in~ (pkg_parents)
| where FileName in~ (trufflehog)
   or ProcessCommandLine has_any (secret_path_tokens)
   or ProcessCommandLine has_any (env_tokens)
   or ProcessCommandLine has_any (env_dumpers)
| extend SignalReason = case(
    FileName in~ (trufflehog), "trufflehog spawned by npm/node",
    ProcessCommandLine has_any (secret_path_tokens), "secret file read from npm/node child",
    ProcessCommandLine has_any (env_tokens), "credential env-var referenced from npm/node child",
    ProcessCommandLine has_any (env_dumpers), "env dump from npm/node child",
    "unknown")
| project Timestamp, DeviceName, AccountName, SignalReason,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          GrandparentImage = InitiatingProcessParentFileName,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256, ReportId
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

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
