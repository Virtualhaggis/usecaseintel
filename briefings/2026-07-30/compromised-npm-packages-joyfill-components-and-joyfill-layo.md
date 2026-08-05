# [CRIT] Compromised npm Packages: @joyfill/components and @joyfill/layouts Ship an Obfuscated Remote Access Trojan

**Source:** StepSecurity
**Published:** 2026-07-30
**Article:** https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise

## Threat Profile

Back to Blog Threat Intel Compromised npm Packages: @joyfill/components and @joyfill/layouts Ship an Obfuscated Remote Access Trojan Malicious 2773 beta versions of @joyfill/components and @joyfill/layouts carry an obfuscated remote access trojan and credential stealer that run on import. Here is how it works and how to check if you are affected. Varun Sharma View LinkedIn July 28, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav..…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `166.88.134.62`
- **IPv4 (defanged):** `23.27.13.43`
- **IPv4 (defanged):** `198.105.127.210`
- **IPv4 (defanged):** `23.27.202.27`
- **Domain (defanged):** `api.trongrid.io`
- **Domain (defanged):** `fullnode.mainnet.aptoslabs.com`
- **Domain (defanged):** `bsc-dataseed.binance.org`
- **Domain (defanged):** `bsc-rpc.publicnode.com`
- **Domain (defanged):** `ip-api.com`
- **SHA256:** `26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18`
- **SHA256:** `36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c`
- **SHA256:** `cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059** — Command and Scripting Interpreter
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Installation of compromised @joyfill/components or @joyfill/layouts 2773 beta packages

`UC_94_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process=*@joyfill/components* OR Processes.process=*@joyfill/layouts*) Processes.process=*2773* by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","npm-cli.js","node.exe","yarn.exe","pnpm.exe") or InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("@joyfill/components","@joyfill/layouts")
| where ProcessCommandLine has "2773"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Node.js host callout to Joyfill DEV#POPPER RAT C2 infrastructure

`UC_94_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("166.88.134.62","23.27.13.43","198.105.127.210","23.27.202.27") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("166.88.134.62","23.27.13.43","198.105.127.210","23.27.202.27")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Node.js spawning a shell or detached node -e child (Joyfill RAT execution)

`UC_94_10` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.parent_process_name=node.exe (Processes.process_name IN (cmd.exe,powershell.exe,pwsh.exe,wscript.exe,cscript.exe) OR (Processes.process_name=node.exe AND Processes.process=*-e*)) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "node.exe"
| where (FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe"))
     or (FileName =~ "node.exe" and ProcessCommandLine has " -e ")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Joyfill RAT persistence injection into developer tool modules (VS Code / Discord / GitHub Desktop / npm)

`UC_94_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path=*@vscode*deviceid* OR Filesystem.file_path=*GitHub Desktop* OR Filesystem.file_path=*\\discord\\* OR Filesystem.file_path=*node_modules\\npm\\bin*) Filesystem.file_name=*.js by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileModified","FileCreated")
| where InitiatingProcessFileName =~ "node.exe"
| where FolderPath has_any (@"\@vscode\deviceid", "@vscode/deviceid", @"\GitHub Desktop\", @"\discord\", @"node_modules\npm\bin")
| where FileName endswith ".js"
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType, SHA256
| order by Timestamp desc
```

### Known-malicious Joyfill package bundle hash observed on disk

`UC_94_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18" OR Filesystem.file_hash="36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c" OR Filesystem.file_hash="cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let joyfillHashes = dynamic(["26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18","36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c","cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (joyfillHashes)
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Compromised @joyfill package artifacts written under node_modules or lock files

`UC_94_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path=*node_modules\\@joyfill\\components* OR Filesystem.file_path=*node_modules\\@joyfill\\layouts*) (Filesystem.file_name IN (index.js,index.esm.js,joyfill.min.js,index.cjs.js,index.es.js,package.json)) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any (@"node_modules\@joyfill\components", @"node_modules\@joyfill\layouts", "node_modules/@joyfill/components", "node_modules/@joyfill/layouts")
        and FileName in~ ("index.js","index.esm.js","joyfill.min.js","index.cjs.js","index.es.js","package.json"))
   or (FileName in~ ("package-lock.json","yarn.lock","pnpm-lock.yaml") and InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Compromised npm Packages: @joyfill/components and @joyfill/layouts Ship an Obfus

`UC_94_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Compromised npm Packages: @joyfill/components and @joyfill/layouts Ship an Obfus ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","esm.js","min.js","cjs.js","main.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.npm*" OR Filesystem.file_name IN ("node.js","esm.js","min.js","cjs.js","main.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Compromised npm Packages: @joyfill/components and @joyfill/layouts Ship an Obfus
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "esm.js", "min.js", "cjs.js", "main.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.npm") or FileName in~ ("node.js", "esm.js", "min.js", "cjs.js", "main.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `166.88.134.62`, `23.27.13.43`, `198.105.127.210`, `23.27.202.27`, `api.trongrid.io`, `fullnode.mainnet.aptoslabs.com`, `bsc-dataseed.binance.org`, `bsc-rpc.publicnode.com` _(+1 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18`, `36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c`, `cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
