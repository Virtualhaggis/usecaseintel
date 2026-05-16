# [CRIT] Mini Shai-Hulud Targets SAP npm Packages With a Bun-Based Secret Stealer

**Source:** Aikido
**Published:** 2026-04-29
**Article:** https://www.aikido.dev/blog/mini-shai-hulud-has-appeared

## Threat Profile

Blog Vulnerabilities & Threats Mini Shai-Hulud Targets SAP npm Packages With a Bun-Based Secret Stealer Mini Shai-Hulud Targets SAP npm Packages With a Bun-Based Secret Stealer Written by Raphael Silva Published on: Apr 29, 2026 A new npm supply-chain compromise is targeting the SAP developer ecosystem.
The affected packages we are tracking so far are:
@cap-js/sqlite - v2.2.2 
@cap-js/postgres - v2.2.2 
@cap-js/db-service - v2.10.1 
mbt@1.2.48 
The pattern is familiar but also a bit different: a…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34`
- **SHA256:** `6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95`
- **SHA256:** `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7`
- **SHA1:** `a959014aa7b7fc37a9b5730c951776e7db2920a6`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1546.016** — Installer Packages
- **T1059.007** — JavaScript
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1552.001** — Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] npm preinstall hook executes 'node setup.mjs' / 'bun execution.js' (Mini Shai-Hulud SAP supply chain)

`UC_234_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents values(Processes.process_path) as paths from datamodel=Endpoint.Processes where ((Processes.process_name IN ("node.exe","node") AND Processes.process="*setup.mjs*") OR (Processes.process_name IN ("bun","bun.exe") AND Processes.process="*execution.js*")) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (
    (FileName has_any ("node.exe","node") and ProcessCommandLine has "setup.mjs")
    or (FileName has_any ("bun","bun.exe") and ProcessCommandLine has "execution.js")
  )
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud 'OhNoWhatsGoingOnWithGitHub' dead-drop keyword in outbound URL

`UC_234_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as users values(Web.http_user_agent) as ua from datamodel=Web.Web where (Web.url="*OhNoWhatsGoingOnWithGitHub*" OR Web.url="*search/commits?q=OhNoWhatsGoingOnWithGitHub*") by Web.dest Web.src Web.site | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  ( DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has "OhNoWhatsGoingOnWithGitHub"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              Signal="network" ),
  ( DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "OhNoWhatsGoingOnWithGitHub"
       or InitiatingProcessCommandLine has "OhNoWhatsGoingOnWithGitHub"
    | project Timestamp, DeviceName, AccountName,
              RemoteUrl="", RemoteIP="", RemotePort=0,
              InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine,
              Signal="process" )
| order by Timestamp desc
```

### [LLM] Mini Shai-Hulud known SHA256 IOC match (setup.mjs / execution.js / runner-memory dumper)

`UC_234_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.file_name) as files values(Filesystem.user) as users from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34","6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95","29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7") by Filesystem.dest Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let bad_hashes = dynamic([
    "4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34",
    "6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95",
    "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7"
]);
union
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (bad_hashes)
    | project Timestamp, DeviceName,
              Actor=InitiatingProcessAccountName,
              FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              EventClass="FileEvent" ),
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (bad_hashes)
       or InitiatingProcessSHA256 in (bad_hashes)
    | project Timestamp, DeviceName, Actor=AccountName,
              FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              EventClass="ProcessEvent" ),
  ( DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (bad_hashes)
    | project Timestamp, DeviceName, Actor=InitiatingProcessAccountName,
              FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine="",
              EventClass="ImageLoad" )
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — Mini Shai-Hulud Targets SAP npm Packages With a Bun-Based Secret Stealer

`UC_234_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mini Shai-Hulud Targets SAP npm Packages With a Bun-Based Secret Stealer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("execution.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("execution.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Mini Shai-Hulud Targets SAP npm Packages With a Bun-Based Secret Stealer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("execution.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4066781fa830224c8bbcc3aa005a396657f9c8f9016f9a64ad44a9d7f5f45e34`, `6f933d00b7d05678eb43c90963a80b8947c4ae6830182f89df31da9f568fea95`, `29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7`, `a959014aa7b7fc37a9b5730c951776e7db2920a6`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
