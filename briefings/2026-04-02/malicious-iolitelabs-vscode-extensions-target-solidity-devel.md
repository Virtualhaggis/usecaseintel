# [HIGH] Malicious IoliteLabs VSCode Extensions Target Solidity Developers on Windows, macOS, and Linux with Backdoor

**Source:** StepSecurity
**Published:** 2026-04-02
**Article:** https://www.stepsecurity.io/blog/malicious-iolitelabs-vscode-extensions-target-solidity-developers-on-windows-macos-and-linux-with-backdoor

## Threat Profile

Back to Blog Threat Intel Malicious IoliteLabs VSCode Extensions Target Solidity Developers on Windows, macOS, and Linux with Backdoor A supply chain attack targeting Solidity and Web3 developers has been discovered across three IoliteLabs VSCode extensions (solidity-macos, solidity-windows, and solidity-linux) embedding obfuscated backdoors that download remote payloads and establish persistence on all major platforms. StepSecurity is actively investigating this incident and will publish a full…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `rraghh.com`
- **Domain (defanged):** `cdn.rraghh.com`
- **Domain (defanged):** `oortt.com`
- **SHA256:** `fcd398abc51fd16e8bc93ef8d88a23d7dec28081b6dfce4b933020322a610508`
- **SHA256:** `e903ae267bf7ed1d02b218c1dc7cf6d87257e87de9fbda411a13f9154716bfa3`

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
- **T1543.001** — Persistence (article-specific)
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1105** — Ingress Tool Transfer
- **T1218.010** — System Binary Proxy Execution: Regsvr32
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] IoliteLabs VSCode extension dropper: VS Code child process reaching rraghh.com / oortt.com C2

`UC_310_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("Code.exe","Code - Insiders.exe","Cursor.exe","Windsurf.exe","VSCodium.exe","Positron.exe") OR Processes.parent_process_path="*\\Microsoft VS Code\\Code.exe" OR Processes.parent_process_path="*\\Cursor\\Cursor.exe") AND (Processes.process="*rraghh.com*" OR Processes.process="*oortt.com*" OR Processes.process="*cdn.rraghh.com*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("Code.exe","Code - Insiders.exe","Cursor.exe","Windsurf.exe","VSCodium.exe","Positron.exe")
   or InitiatingProcessFolderPath has_any (@"\Microsoft VS Code\", @"\Cursor\", @"\Windsurf\", @"\VSCodium\")
| where ProcessCommandLine has_any ("rraghh.com","oortt.com","cdn.rraghh.com")
   or (ProcessCommandLine has "curl" and ProcessCommandLine has_any (@"%TEMP%\1.bat", @"\Temp\1.bat"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] IoliteLabs Stage-2 regsvr32 LOLbin loading ntuser DLL from fake Chrome\ChromeUpdate path

`UC_310_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="regsvr32.exe" AND Processes.process="*ntuser*" AND (Processes.process="*\\Chrome\\ChromeUpdate*" OR Processes.process="* /i *") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where match(process,"(?i)regsvr32.*\\s/(s|i)\\b.*ntuser") OR match(process,"(?i)Chrome\\\\ChromeUpdate\\\\ntuser") | sort - firstTime
```

**Defender KQL:**
```kql
let _knownHashes = dynamic(["5f9c09c2c432a6b94f2200455065bcfd1237f8a01b913a7c9e37f164ff99a84c","e903ae267bf7ed1d02b218c1dc7cf6d87257e87de9fbda411a13f9154716bfa3"]);
let ProcSig = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "regsvr32.exe"
    | where ProcessCommandLine has "ntuser"
    | where ProcessCommandLine has @"\Chrome\ChromeUpdate"
         or ProcessCommandLine matches regex @"(?i)regsvr32(\.exe)?\s+/s\s+/i\s+.*ntuser"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="ProcessExec";
let HashSig = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (_knownHashes)
       or (FileName =~ "ntuser" and FolderPath has @"\Chrome\ChromeUpdate")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine=tostring(SHA256), Source="FileWrite";
union ProcSig, HashSig
| order by Timestamp desc
```

### [LLM] IoliteLabs IOC sweep: rraghh.com / oortt.com hostnames + campaign file hashes

`UC_310_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*rraghh.com*" OR Web.url="*oortt.com*" OR Web.dest="*rraghh.com*" OR Web.dest="*oortt.com*") by Web.src Web.user Web.url Web.dest | `drop_dm_object_name(Web)`) | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*rraghh.com" OR DNS.query="*oortt.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | rename src as Web_src query as Web_url] | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("fcd398abc51fd16e8bc93ef8d88a23d7dec28081b6dfce4b933020322a610508","e903ae267bf7ed1d02b218c1dc7cf6d87257e87de9fbda411a13f9154716bfa3","5f9c09c2c432a6b94f2200455065bcfd1237f8a01b913a7c9e37f164ff99a84c") OR Filesystem.file_name IN ("7WhiteSmoke.msi","calc.bat") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | sort - firstTime
```

**Defender KQL:**
```kql
let _iocHashes = dynamic(["fcd398abc51fd16e8bc93ef8d88a23d7dec28081b6dfce4b933020322a610508","e903ae267bf7ed1d02b218c1dc7cf6d87257e87de9fbda411a13f9154716bfa3","5f9c09c2c432a6b94f2200455065bcfd1237f8a01b913a7c9e37f164ff99a84c"]);
let _iocDomains = dynamic(["rraghh.com","oortt.com","cdn.rraghh.com"]);
let Net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (_iocDomains) or tostring(RemoteIP) in (_iocDomains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Indicator=RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="Network";
let Dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q endswith "rraghh.com" or Q endswith "oortt.com"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Indicator=Q, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DNS";
let Files = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (_iocHashes)
       or (FileName =~ "7WhiteSmoke.msi")
       or (FileName =~ "1.bat" and FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\"))
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Indicator=strcat(FileName," / ",SHA256), InitiatingProcessFileName, InitiatingProcessCommandLine, Source="File";
union Net, Dns, Files
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

### Article-specific behavioural hunt — Malicious IoliteLabs VSCode Extensions Target Solidity Developers on Windows, ma

`UC_310_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious IoliteLabs VSCode Extensions Target Solidity Developers on Windows, ma ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js","extension.js","calc.bat","whitesmoke.msi","7whitesmoke.msi","doc.sh","node.js","dev-machine-guard.sh","stepsecurity-dev-machine-guard.sh") OR Processes.process_path="*%APPDATA%\Chrome\ChromeUpdate\*" OR Processes.process_path="*%APPDATA%\Chrome\ChromeUpdate\ntuser*" OR Processes.process_path="*%USERPROFILE%\Documents\7WhiteSmoke.msi*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%APPDATA%\Chrome\ChromeUpdate\*" OR Filesystem.file_path="*%APPDATA%\Chrome\ChromeUpdate\ntuser*" OR Filesystem.file_path="*%USERPROFILE%\Documents\7WhiteSmoke.msi*" OR Filesystem.file_path="*/tmp/system_updater.log*" OR Filesystem.file_path="*/Library/LaunchAgents/com.apple.system.updater.plist*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("index.js","extension.js","calc.bat","whitesmoke.msi","7whitesmoke.msi","doc.sh","node.js","dev-machine-guard.sh","stepsecurity-dev-machine-guard.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\Software\\Chrome\\ChromeUpdate*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious IoliteLabs VSCode Extensions Target Solidity Developers on Windows, ma
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js", "extension.js", "calc.bat", "whitesmoke.msi", "7whitesmoke.msi", "doc.sh", "node.js", "dev-machine-guard.sh", "stepsecurity-dev-machine-guard.sh") or FolderPath has_any ("%APPDATA%\Chrome\ChromeUpdate\", "%APPDATA%\Chrome\ChromeUpdate\ntuser", "%USERPROFILE%\Documents\7WhiteSmoke.msi"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%APPDATA%\Chrome\ChromeUpdate\", "%APPDATA%\Chrome\ChromeUpdate\ntuser", "%USERPROFILE%\Documents\7WhiteSmoke.msi", "/tmp/system_updater.log", "/Library/LaunchAgents/com.apple.system.updater.plist", "/dev/null") or FileName in~ ("index.js", "extension.js", "calc.bat", "whitesmoke.msi", "7whitesmoke.msi", "doc.sh", "node.js", "dev-machine-guard.sh", "stepsecurity-dev-machine-guard.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\Software\Chrome\ChromeUpdate")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `rraghh.com`, `cdn.rraghh.com`, `oortt.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `fcd398abc51fd16e8bc93ef8d88a23d7dec28081b6dfce4b933020322a610508`, `e903ae267bf7ed1d02b218c1dc7cf6d87257e87de9fbda411a13f9154716bfa3`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
