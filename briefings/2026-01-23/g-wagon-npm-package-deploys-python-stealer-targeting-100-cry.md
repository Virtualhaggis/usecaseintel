# [HIGH] G_Wagon: npm Package Deploys Python Stealer Targeting 100+ Crypto Wallets

**Source:** Aikido
**Published:** 2026-01-23
**Article:** https://www.aikido.dev/blog/npm-malware-g-wagon-python-stealer-crypto-wallets

## Threat Profile

Blog Vulnerabilities & Threats G_Wagon: npm Package Deploys Python Stealer Targeting 100+ Crypto Wallets G_Wagon: npm Package Deploys Python Stealer Targeting 100+ Crypto Wallets Written by Charlie Eriksen Published on: Jan 23, 2026 At 08:46 UTC on January 23rd, 2026, our malware detection system flagged a package called ansi-universal-ui . The name sounds like a boring UI component library. The description even says it's " a lightweight, modular UI component system for modern web applications. …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `nyc.cloud.appwrite.io`
- **Domain (defanged):** `fra.cloud.appwrite.io`
- **SHA256:** `7de334b0530e168fcf70335aa73a26a0b483e864c415d02980fe5e6b07f6af85`
- **SHA256:** `00f1e82321a400fa097fc47edc1993203747223567a2a147ed458208376e39a1`
- **SHA256:** `1979bf6ff76d2adbd394e1288d75ab04abfb963109e81294a28d0629f90b77c7`
- **SHA256:** `ecde55186231f1220218880db30d704904dd3ff6b3096c745a1e15885d6e99cc`
- **SHA256:** `eb19a25480916520aecc30c54afdf6a0ce465db39910a5c7a01b1b3d1f693c4c`
- **SHA256:** `ff514331b93a76c9bbf1f16cdd04e79c576d8efd0d3587cb3665620c9bf49432`
- **SHA256:** `a576844e131ed6b51ebdfa7cd509233723b441a340529441fb9612f226fafe52`
- **SHA256:** `e25f5d5b46368ed03562625b53efd24533e20cd1d42bc64b1ebf041cacab8941`
- **SHA1:** `3639363865613536303033313663313238663232`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1547** — Boot or Logon Autostart Execution
- **T1070.004** — Indicator Removal: File Deletion (counter prevents reinfection)
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1140** — Deobfuscate/Decode Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] G_Wagon npm stealer C2 egress to specific Appwrite project/bucket IDs

`UC_467_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as users from datamodel=Web where (Web.dest IN ("nyc.cloud.appwrite.io","fra.cloud.appwrite.io") OR Web.url="*688625a0000f8a1b71e8*" OR Web.url="*6886229e003d46469fab*" OR Web.url="*6968ea5600316c128f22*" OR Web.url="*6968e9e9000ee4ac710c*") by Web.src Web.dest Web.http_method Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any ("nyc.cloud.appwrite.io","fra.cloud.appwrite.io"))
   or RemoteUrl has_any ("688625a0000f8a1b71e8","6886229e003d46469fab","6968ea5600316c128f22","6968e9e9000ee4ac710c")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] G_Wagon stealer execution-counter file (.gwagon_status) created in user home

`UC_467_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where Filesystem.file_name=".gwagon_status" by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ ".gwagon_status"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] node.exe spawning Python interpreter with stdin pipe (G_Wagon in-memory dropper chain)

`UC_467_12` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_path) as image_paths values(Processes.parent_process) as parent_cmdlines from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" (Processes.process_name IN ("python.exe","python3.exe","python","python3") OR Processes.process_name IN ("tar.exe","tar")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | where (match(process,"(?i)python(\.exe)?\s+-\s*$") OR match(process,"(?i)python(\.exe)?\s+-\s+") OR (match(process,"(?i)tar(\.exe)?") AND match(process,"-x") AND match(process,"-f\s+-")) OR match(process,"(?i)latest_script\.py")) | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ ("python.exe","python3.exe","python","python3","tar.exe","tar")
| where (FileName has "python" and (ProcessCommandLine matches regex @"(?i)python(\.exe)?\s+-\s*$" or ProcessCommandLine matches regex @"(?i)python(\.exe)?\s+-\s+"))
   or (FileName has "tar" and ProcessCommandLine has_all ("-x","-f") and ProcessCommandLine matches regex @"-f\s+-\s")
   or ProcessCommandLine has "latest_script.py"
   or InitiatingProcessSHA256 in ("ecde55186231f1220218880db30d704904dd3ff6b3096c745a1e15885d6e99cc","eb19a25480916520aecc30c54afdf6a0ce465db39910a5c7a01b1b3d1f693c4c","ff514331b93a76c9bbf1f16cdd04e79c576d8efd0d3587cb3665620c9bf49432","a576844e131ed6b51ebdfa7cd509233723b441a340529441fb9612f226fafe52")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, FileName, ProcessCommandLine, FolderPath, SHA256
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

### Article-specific behavioural hunt — G_Wagon: npm Package Deploys Python Stealer Targeting 100+ Crypto Wallets

`UC_467_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — G_Wagon: npm Package Deploys Python Stealer Targeting 100+ Crypto Wallets ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("latest_script.py","index.js") OR Processes.process="*DownloadString*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("latest_script.py","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — G_Wagon: npm Package Deploys Python Stealer Targeting 100+ Crypto Wallets
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("latest_script.py", "index.js") or ProcessCommandLine has_any ("DownloadString"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("latest_script.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `nyc.cloud.appwrite.io`, `fra.cloud.appwrite.io`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7de334b0530e168fcf70335aa73a26a0b483e864c415d02980fe5e6b07f6af85`, `00f1e82321a400fa097fc47edc1993203747223567a2a147ed458208376e39a1`, `1979bf6ff76d2adbd394e1288d75ab04abfb963109e81294a28d0629f90b77c7`, `ecde55186231f1220218880db30d704904dd3ff6b3096c745a1e15885d6e99cc`, `eb19a25480916520aecc30c54afdf6a0ce465db39910a5c7a01b1b3d1f693c4c`, `ff514331b93a76c9bbf1f16cdd04e79c576d8efd0d3587cb3665620c9bf49432`, `a576844e131ed6b51ebdfa7cd509233723b441a340529441fb9612f226fafe52`, `e25f5d5b46368ed03562625b53efd24533e20cd1d42bc64b1ebf041cacab8941` _(+1 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
