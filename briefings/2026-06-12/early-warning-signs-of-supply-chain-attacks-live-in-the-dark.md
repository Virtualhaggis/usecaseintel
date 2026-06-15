# [CRIT] Early Warning Signs of Supply-Chain Attacks Live in the Dark Web

**Source:** BleepingComputer
**Published:** 2026-06-12
**Article:** https://www.bleepingcomputer.com/news/security/early-warning-signs-of-supply-chain-attacks-live-in-the-dark-web/

## Threat Profile

Early Warning Signs of Supply-Chain Attacks Live in the Dark Web 
Sponsored by Flare 
June 12, 2026
10:01 AM
0 
Supply-chain attacks are usually discussed after they become visible: a malicious package, a compromised software update, a malicious extension, or a breach involving a trusted vendor. But before an incident reaches that stage, the early warning signs may look much less obvious.
In underground forums and marketplaces, supply-chain relevance does not always appear under a clear label. A…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33634`
- **Domain (defanged):** `webhook.site`
- **SHA256:** `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **SHA256:** `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- **SHA256:** `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`
- **SHA256:** `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- **SHA256:** `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`
- **SHA256:** `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`
- **SHA256:** `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
- **SHA256:** `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1546** — Event Triggered Execution
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1199** — Trusted Relationship
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Shai-Hulud npm worm — shai-hulud-workflow.yml dropped into .github/workflows/

`UC_35_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="shai-hulud-workflow.yml" OR Filesystem.file_path="*\\.github\\workflows\\shai-hulud*" OR Filesystem.file_path="*/.github/workflows/shai-hulud*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName =~ "shai-hulud-workflow.yml"
   or FolderPath has @"\.github\workflows\shai-hulud"
   or FolderPath has "/.github/workflows/shai-hulud"
| project Timestamp, DeviceName,
          AccountName = InitiatingProcessAccountName,
          FolderPath, FileName, SHA256,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          GrandParent = InitiatingProcessParentFileName
| order by Timestamp desc
```

### Shai-Hulud worm exfil — outbound to webhook.site/bb8ca5f6 from developer or CI process

`UC_35_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.url) as url from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7*" OR (All_Traffic.url="*webhook.site*" AND All_Traffic.process_name IN ("node.exe","npm.exe","npm-cli.js","yarn.exe","pnpm.exe","git.exe","runner.exe","Runner.Worker.exe"))) by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.dest All_Traffic.url
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ShaiHuludUuid = "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7";
let DevProcs = dynamic(["node.exe","npm.exe","yarn.exe","pnpm.exe","git.exe","runner.exe","Runner.Worker.exe","powershell.exe","pwsh.exe","bash.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has "webhook.site"
| where RemoteUrl has ShaiHuludUuid
      or InitiatingProcessFileName in~ (DevProcs)
| project Timestamp, DeviceName,
          AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### TruffleHog binary spawned by npm/node — Shai-Hulud secret harvest

`UC_35_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("trufflehog","trufflehog.exe","trufflehog3","trufflehog3.exe") OR Processes.process="*trufflehog*filesystem*" OR Processes.process="*trufflehog*git*") AND Processes.parent_process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe","runner.exe","Runner.Worker.exe","bash.exe","sh.exe","cmd.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName matches regex @"(?i)^trufflehog([0-9])?(\.exe)?$"
        or ProcessCommandLine has "trufflehog filesystem"
        or ProcessCommandLine has "trufflehog git"
        or ProcessCommandLine has "trufflehog --json")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npm-cli.js","yarn.exe","pnpm.exe","runner.exe","Runner.Worker.exe","bash.exe","sh.exe","cmd.exe","powershell.exe","pwsh.exe")
     or InitiatingProcessParentFileName in~ ("node.exe","npm.exe","yarn.exe","runner.exe")
| project Timestamp, DeviceName,
          AccountName, ProcessCommandLine, FolderPath, SHA256,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          GrandParent = InitiatingProcessParentFileName
| order by Timestamp desc
```

### Shai-Hulud bundle.js — known-bad SHA256 written to disk

`UC_35_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09","62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0","f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068","cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd","a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a","b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777","dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c","4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db") OR (Filesystem.file_name="bundle.js" AND Filesystem.file_path="*\\node_modules\\*" AND Filesystem.process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let KnownHashes = dynamic([
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"]);
union isfuzzy=true
(DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (KnownHashes)
        or (FileName =~ "bundle.js" and FolderPath has @"\node_modules\" and InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe"))
   | project Timestamp, DeviceName, EventTable="FileEvent",
             AccountName=InitiatingProcessAccountName,
             FolderPath, FileName, SHA256,
             ParentImage=InitiatingProcessFileName,
             ParentCmd=InitiatingProcessCommandLine),
(DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (KnownHashes) or InitiatingProcessSHA256 in (KnownHashes)
   | project Timestamp, DeviceName, EventTable="ProcessEvent",
             AccountName, FolderPath, FileName=FileName, SHA256,
             ParentImage=InitiatingProcessFileName,
             ParentCmd=InitiatingProcessCommandLine)
| order by Timestamp desc
```

### OAuth consent grant to unfamiliar third-party AI / SaaS app — Vercel-style trust chain attack

`UC_35_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let Lookback = 30d;
let KnownApps = AADSignInEventsBeta
    | where Timestamp between (ago(Lookback) .. ago(2d))
    | summarize by ApplicationId;
CloudAppEvents
| where Timestamp > ago(2d)
| where ActionType has_any ("Consent to application","Add app role assignment grant to user","Add delegated permission grant")
| extend AppName = tostring(parse_json(tostring(RawEventData)).Target[0].ID)
| extend ConsentedApp = tostring(ActivityObjects[0].Name),
         ConsentedAppId = tostring(ActivityObjects[0].Id),
         GrantedScopes = tostring(parse_json(tostring(RawEventData)).ModifiedProperties)
| where ConsentedAppId !in (KnownApps)
| where GrantedScopes has_any ("Mail.Read","Mail.ReadWrite","Files.Read.All","Files.ReadWrite.All","Sites.Read.All","User.Read.All","Directory.Read.All","offline_access")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode,
          IsAdminOperation, ConsentedApp, ConsentedAppId, GrantedScopes,
          UserAgent, ActionType
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33634`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `webhook.site`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`, `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`, `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`, `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`, `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`, `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
