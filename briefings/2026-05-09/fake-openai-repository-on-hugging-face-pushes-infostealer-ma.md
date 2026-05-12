# [HIGH] Fake OpenAI repository on Hugging Face pushes infostealer malware

**Source:** BleepingComputer
**Published:** 2026-05-09
**Article:** https://www.bleepingcomputer.com/news/security/fake-openai-repository-on-hugging-face-pushes-infostealer-malware/

## Threat Profile

Fake OpenAI repository on Hugging Face pushes infostealer malware 
By Bill Toulas 
May 9, 2026
10:26 AM
0 
A malicious Hugging Face repository that reached the platform’s trending list impersonated OpenAI’s “Privacy Filter” project to deliver information-stealing malware to Windows users.
The repository briefly reached #1 on Hugging Face and accumulated 244,000 downloads before the platform responded to reports and removed it.
The Hugging Face platform lets developers and researchers share AI mo…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `recargapopular.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1105** — Ingress Tool Transfer
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Python interpreter spawns hidden-window PowerShell fetching remote JSON payload (loader.py handoff)

`UC_125_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="python.exe" Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*-w*hidden*" OR Processes.process="*WindowStyle*Hidden*" OR Processes.process="*-WindowStyle*1*") (Processes.process="*Invoke-WebRequest*" OR Processes.process="*DownloadString*" OR Processes.process="*WebClient*" OR Processes.process="*Invoke-RestMethod*" OR Processes.process="*.json*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "python.exe"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)-w(in)?(dow)?s(tyle)?\s+(h(idden)?|1)"
| where ProcessCommandLine has_any ("Invoke-WebRequest","DownloadString","WebClient","Invoke-RestMethod",".json","FromBase64String")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Add-MpPreference exclusion for sefirah / start.bat (Hugging Face campaign defense evasion)

`UC_125_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe") (Processes.process="*Add-MpPreference*" OR Processes.process="*Set-MpPreference*") (Processes.process="*Exclusion*") (Processes.process="*sefirah*" OR Processes.process="*start.bat*" OR Processes.process="*Open-OSS*" OR Processes.process="*privacy-filter*" OR Processes.process="*\\AppData\\Local\\Temp\\*" OR Processes.process="*\\ProgramData\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| where ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference")
| where ProcessCommandLine has_any ("ExclusionPath","ExclusionProcess","ExclusionExtension")
| where ProcessCommandLine has_any ("sefirah","start.bat","Open-OSS","privacy-filter")
   or ProcessCommandLine has_any (@"\AppData\Local\Temp\", @"\ProgramData\", @"\Public\", @"\Users\Public\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildCmd = ProcessCommandLine,
          IntegrityLevel = ProcessIntegrityLevel
| order by Timestamp desc
```

### [LLM] Outbound DNS / network connection to sefirah C2 recargapopular.com

`UC_125_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="recargapopular.com" OR DNS.query="*.recargapopular.com") by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*recargapopular.com*" OR Web.dest="recargapopular.com") by Web.src Web.dest Web.url Web.user | `drop_dm_object_name(Web)` ] | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="recargapopular.com" OR All_Traffic.dest_host="*.recargapopular.com") by All_Traffic.src All_Traffic.dest_host All_Traffic.app | `drop_dm_object_name(All_Traffic)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let c2 = dynamic(["recargapopular.com",".recargapopular.com"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "recargapopular.com"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Source = "Network", RemoteUrl, RemoteIP, RemotePort,
              Process = InitiatingProcessFileName, Cmd = InitiatingProcessCommandLine,
              SHA256 = InitiatingProcessSHA256 ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).query)
    | where Q has "recargapopular.com"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Source = "DNS", RemoteUrl = Q, RemoteIP = "", RemotePort = int(null),
              Process = InitiatingProcessFileName, Cmd = InitiatingProcessCommandLine,
              SHA256 = InitiatingProcessSHA256 )
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

### Article-specific behavioural hunt — Fake OpenAI repository on Hugging Face pushes infostealer malware

`UC_125_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fake OpenAI repository on Hugging Face pushes infostealer malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("loader.py","start.bat"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("loader.py","start.bat"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fake OpenAI repository on Hugging Face pushes infostealer malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("loader.py", "start.bat"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("loader.py", "start.bat"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `recargapopular.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
