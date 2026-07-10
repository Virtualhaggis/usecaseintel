# [HIGH] Everybody's shipping code they can't read

**Source:** Aikido
**Published:** 2026-06-25
**Article:** https://www.aikido.dev/blog/shipping-code-they-cant-read

## Threat Profile

Blog News Everybody's shipping code they can't read Everybody's shipping code they can't read Written by Samuel Vandamme Published on: Jun 25, 2026 You used to be able to spot a developer. They had the black and green terminal, the editor with seventeen files open, and uncanny ability to exit vim (`esc :q!` if you didn’t know). Writing software had a high bar, and that bar kept most people out.
Open something like Claude Cowork, type "build me a tool that cleans up this spreadsheet and emails me…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.254.164.92`
- **IPv4 (defanged):** `23.254.164.123`
- **Domain (defanged):** `hwsrv-1327786.hostwindsdns.com`
- **Domain (defanged):** `hwsrv-1327785.hostwindsdns.com`
- **SHA256:** `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`
- **SHA256:** `c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638`
- **SHA256:** `cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066`
- **SHA256:** `9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9`
- **SHA256:** `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1543.002** — Create or Modify System Process: Systemd Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### easy-day-js npm postinstall dropper: node executing setup.cjs --no-warnings

`UC_200_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("node.exe","node") Processes.process="*setup.cjs*" Processes.process="*--no-warnings*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe","node")
| where ProcessCommandLine has "setup.cjs" and ProcessCommandLine has "--no-warnings"
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildCmd = ProcessCommandLine,
          FolderPath, SHA256
| order by Timestamp desc
```

### easy-day-js stealer C2 beacon to Hostwinds 23.254.164.0/24 (ports 8000/443)

`UC_200_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="23.254.164.92" OR All_Traffic.dest_ip="23.254.164.123" OR All_Traffic.dest="teams.onweblive.org" OR All_Traffic.dest="maskasd.com") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("23.254.164.92","23.254.164.123")
   or RemoteUrl has_any ("teams.onweblive.org","maskasd.com","onweblive.org","hwsrv-1327786.hostwindsdns.com","hwsrv-1327785.hostwindsdns.com")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### easy-day-js Windows persistence: Run key 'NvmProtocal' / protocal.cjs autostart

`UC_200_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_value_name="NvmProtocal" OR Registry.registry_value_data="*protocal.cjs*" OR Registry.registry_value_data="*NodePackages*" OR Registry.registry_value_data="*com.nvm.protocal*") by Registry.dest Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where (RegistryKey has @"\CurrentVersion\Run" and RegistryValueName =~ "NvmProtocal")
   or RegistryValueData has_any ("protocal.cjs","NodePackages","com.nvm.protocal")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### easy-day-js implant artifacts dropped: protocal.cjs / NodePackages / cross-OS persistence files

`UC_200_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="protocal.cjs" OR Filesystem.file_name="nvmconf.service" OR Filesystem.file_name="com.nvm.protocal.plist" OR Filesystem.file_name=".pkg_history" OR Filesystem.file_name=".pkg_logs" OR Filesystem.file_path="*\\NodePackages\\*" OR Filesystem.file_path="*/NodePackages/*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("protocal.cjs","nvmconf.service","com.nvm.protocal.plist",".pkg_history",".pkg_logs")
   or FolderPath has "NodePackages"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
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
  - IP / domain IOC(s): `23.254.164.92`, `23.254.164.123`, `hwsrv-1327786.hostwindsdns.com`, `hwsrv-1327785.hostwindsdns.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`, `c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638`, `cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066`, `9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9`, `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
