# [CRIT] Fake Roblox Xeno script launcher pushes infostealer, RAT malware

**Source:** BleepingComputer
**Published:** 2026-08-03
**Article:** https://www.bleepingcomputer.com/news/security/fake-roblox-xeno-script-launcher-pushes-infostealer-rat-malware/

## Threat Profile

Fake Roblox Xeno script launcher pushes infostealer, RAT malware 
By Bill Toulas 
August 3, 2026
03:25 PM
0 


Fake Xeno Executor installers are infecting unsuspecting Roblox players with malware that provides remote access and steals sensitive information.


Xeno Executor is a popular Roblox utility for running scripts that players can use to automate actions or run custom code on the platform, including cheats.


The tool isn’t an official part of the game, so the Roblox client periodica…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `79.110.49.15`
- **Domain (defanged):** `powercat.dog`
- **Domain (defanged):** `ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `alpha.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `beta.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `charlie.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `hotel.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `juliett.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `kilo.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `lima.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **Domain (defanged):** `oscar.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`
- **SHA256:** `A9B4823A1B2C0702A1EB8A1BF18DB2D9C9604D2D2DD98A99F1D388BF7CFA71E3`
- **SHA256:** `A33A96CBD92EEF15116C0C1DCAA8FEB6EEE28A818046AC9576054183E920EEB5`
- **SHA256:** `C0C3A0331B57D10D23A172A79BDF13AB066255DE41774E5A19DD8A8E8446E1FA`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1566** — Phishing
- **T1608.006** — Stage Capabilities: SEO Poisoning
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1106** — Native API
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1105** — Ingress Tool Transfer
- **T1082** — System Information Discovery
- **T1012** — Query Registry
- **T1497.001** — Virtualization/Sandbox Evasion: System Checks

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Browser-delivered fake 'Xeno' Roblox executor archive/binary written to disk

`UC_0_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="xeno.exe" OR Filesystem.file_name="xeno*.zip" OR Filesystem.file_name="Xeno*.zip" OR Filesystem.file_name="xeno*.rar" OR Filesystem.file_name="Xeno*.rar" OR Filesystem.file_name="xeno*.7z") (Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\Desktop\\*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","Discord.exe","Telegram.exe")
| where (FileName =~ "xeno.exe") or (FileName matches regex @"(?i)xeno.*\.(zip|rar|7z|exe)$")
| where isnotempty(FileOriginUrl)
| where not(FileOriginUrl has_any ("roblox.com","xeno.onl"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, FileOriginUrl, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Decoy xeno.exe spawns Java loader / decompiler.exe (Powercat first stage)

`UC_0_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="xeno.exe" AND Processes.process_name IN ("java.exe","javaw.exe","decompiler.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "xeno.exe"
| where FileName in~ ("java.exe","javaw.exe","decompiler.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Powercat obfuscated Java loader invocation (java -cp jd-gui.jar IllllIIllll)

`UC_0_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("java.exe","javaw.exe") AND (Processes.process="*jd-gui.jar*" OR Processes.process="*IllllIIllll*" OR Processes.process="*System.EnterpriseServices.jar*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("java.exe","javaw.exe")
| where ProcessCommandLine has_any ("jd-gui.jar","IllllIIllll","System.EnterpriseServices.jar")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Powercat C2 beacon to powercat.dog and NATO-phonetic *.xyz subdomains

`UC_0_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="powercat.dog" OR DNS.query="*.powercat.dog" OR DNS.query="ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz" OR DNS.query="*.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has "powercat.dog") or (RemoteUrl endswith "ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz") or (RemoteIP == "79.110.49.15")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Powercat host-fingerprint registry key HKCU\Software\Beep written by loader

`UC_0_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Software\\Beep\\*" OR Registry.registry_key_name="*\\Software\\Beep\\*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.process_name | `drop_dm_object_name(Registry)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Software\Beep"
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe","decompiler.exe","xeno.exe","3k3uklt.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Powercat payload staging under %LOCALAPPDATA%\Xeno\workspace and GameDVR-masqueraded DLLs

`UC_0_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\AppData\\Local\\Xeno\\workspace\\*" OR Filesystem.file_name IN ("jd-gui.jar","System.EnterpriseServices.jar","decompiler.exe") OR (Filesystem.file_path="*\\Microsoft\\GameDVR\\*" AND Filesystem.file_name IN ("mscorlib.dll","System.IO.Compression.dll","System.Net.Http.dll","System.EnterpriseServices.dll","nvwgf2umx.dll","avcodec-58.dll","libcef.dll"))) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has @"\AppData\Local\Xeno\workspace")
    or (FileName in~ ("jd-gui.jar","System.EnterpriseServices.jar","decompiler.exe"))
    or (FolderPath has @"\Microsoft\GameDVR" and FileName in~ ("mscorlib.dll","System.IO.Compression.dll","System.Net.Http.dll","System.EnterpriseServices.dll","nvwgf2umx.dll","avcodec-58.dll","libcef.dll"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Article-specific behavioural hunt — Fake Roblox Xeno script launcher pushes infostealer, RAT malware

`UC_0_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fake Roblox Xeno script launcher pushes infostealer, RAT malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("xeno.exe","decompiler.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("xeno.exe","decompiler.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fake Roblox Xeno script launcher pushes infostealer, RAT malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("xeno.exe", "decompiler.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("xeno.exe", "decompiler.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `79.110.49.15`, `powercat.dog`, `ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`, `alpha.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`, `beta.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`, `charlie.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`, `hotel.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz`, `juliett.ce953a0eb08246617b7f849486c4b26a7af37e9d2e8f0e13b3ae1bf0da8a70a.xyz` _(+3 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `A9B4823A1B2C0702A1EB8A1BF18DB2D9C9604D2D2DD98A99F1D388BF7CFA71E3`, `A33A96CBD92EEF15116C0C1DCAA8FEB6EEE28A818046AC9576054183E920EEB5`, `C0C3A0331B57D10D23A172A79BDF13AB066255DE41774E5A19DD8A8E8446E1FA`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
