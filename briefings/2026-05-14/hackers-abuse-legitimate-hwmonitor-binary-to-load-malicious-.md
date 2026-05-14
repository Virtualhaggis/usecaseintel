# [CRIT] Hackers Abuse Legitimate HWMonitor Binary to Load Malicious DLL Payload

**Source:** Cyber Security News
**Published:** 2026-05-14
**Article:** https://cybersecuritynews.com/hackers-abuse-legitimate-hwmonitor-binary/

## Threat Profile

Home Cyber Security News 
Hackers Abuse Legitimate HWMonitor Binary to Load Malicious DLL Payload 
By Tushar Subhra Dutta 
May 14, 2026 
Hackers are once again turning familiar tools against the very users who trust them. A new attack campaign has been discovered in which threat actors weaponized HWMonitor, a widely used hardware monitoring utility developed by CPUID, to silently deliver a remote access trojan known as STX RAT. 
By disguising malware inside what looks like a routine software dow…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`
- **Domain (defanged):** `pub-fd67c956bf8548b7b2cc23bb3774ff0c.r2.dev`
- **Domain (defanged):** `63.zip`
- **Domain (defanged):** `welcome.supp0v3.com`
- **MD5:** `fd67c956bf8548b7b2cc23bb3774ff0c`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1574.001** — DLL Search Order Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1568** — Dynamic Resolution
- **T1620** — Reflective Code Loading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] HWMonitor_x64.exe sideloads CRYPTBASE.dll from non-System32 path (STX RAT)

`UC_13_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=7 (Image="*\\hwmonitor_x64.exe" OR Image="*\\HWMonitor_x64.exe") ImageLoaded="*\\cryptbase.dll" NOT (ImageLoaded="C:\\Windows\\System32\\cryptbase.dll" OR ImageLoaded="C:\\Windows\\SysWOW64\\cryptbase.dll")
| stats min(_time) as firstSeen max(_time) as lastSeen values(ImageLoaded) as loadedPath values(Hashes) as hashes by host, Image, user
| `security_content_ctime(firstSeen)` | `security_content_ctime(lastSeen)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "hwmonitor_x64.exe"
| where FileName =~ "cryptbase.dll"
| where not(FolderPath startswith @"C:\Windows\System32\")
| where not(FolderPath startswith @"C:\Windows\SysWOW64\")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          LoaderPath = InitiatingProcessFolderPath,
          LoadedDllPath = FolderPath,
          LoadedDllName = FileName,
          DllSHA256 = SHA256,
          LoaderSHA256 = InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] STX RAT C2 callback to welcome.supp0v3.com or staging on Cloudflare R2 bucket

`UC_13_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="welcome.supp0v3.com" OR All_Traffic.dest="*.supp0v3.com" OR All_Traffic.dest="pub-fd67c956bf8548b7b2cc23bb3774ff0c.r2.dev" OR All_Traffic.url="*hwmonitor_1.63.zip*") by All_Traffic.src host All_Traffic.app
| `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstSeen)` | `security_content_ctime(lastSeen)`
```

**Defender KQL:**
```kql
let stxC2Domains = dynamic(["welcome.supp0v3.com", "supp0v3.com"]);
let stxStagingHost = "pub-fd67c956bf8548b7b2cc23bb3774ff0c.r2.dev";
let stxStagingFile = "hwmonitor_1.63.zip";
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (stxC2Domains)
        or RemoteUrl has stxStagingHost
        or RemoteUrl has stxStagingFile
    | project Timestamp, DeviceName, InitiatingProcessFileName,
              InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort,
              Source = "DeviceNetworkEvents" ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q has_any (stxC2Domains) or Q has "supp0v3" or Q == stxStagingHost
    | project Timestamp, DeviceName, InitiatingProcessFileName,
              InitiatingProcessCommandLine, RemoteUrl = Q,
              RemoteIP = "", RemotePort = int(null),
              Source = "DnsQueryResponse" )
| order by Timestamp desc
```

### [LLM] HWMonitor_x64.exe makes outbound connection to non-CPUID public infrastructure

`UC_13_10` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="hwmonitor_x64.exe" All_Traffic.dest_category="public" NOT All_Traffic.dest="*.cpuid.com" NOT All_Traffic.dest="cpuid.com" by host All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)` | where count > 0
| `security_content_ctime(firstSeen)` | `security_content_ctime(lastSeen)`
```

**Defender KQL:**
```kql
let knownGoodDomains = dynamic(["cpuid.com", "www.cpuid.com", "download.cpuid.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "hwmonitor_x64.exe"
| where RemoteIPType == "Public"
| where not(RemoteUrl endswith "cpuid.com")
| where not(RemoteUrl in~ (knownGoodDomains))
| extend C2Candidate = coalesce(RemoteUrl, RemoteIP)
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Ports = make_set(RemotePort, 10),
            SampleCmd = any(InitiatingProcessCommandLine),
            LoaderSHA256 = any(InitiatingProcessSHA256)
            by DeviceName, InitiatingProcessAccountName, C2Candidate
| order by FirstSeen desc
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

### Article-specific behavioural hunt — Hackers Abuse Legitimate HWMonitor Binary to Load Malicious DLL Payload

`UC_13_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Abuse Legitimate HWMonitor Binary to Load Malicious DLL Payload ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("hwmonitor_x64.exe","cryptbase.dll","stxbase.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("hwmonitor_x64.exe","cryptbase.dll","stxbase.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Abuse Legitimate HWMonitor Binary to Load Malicious DLL Payload
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("hwmonitor_x64.exe", "cryptbase.dll", "stxbase.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("hwmonitor_x64.exe", "cryptbase.dll", "stxbase.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `pub-fd67c956bf8548b7b2cc23bb3774ff0c.r2.dev`, `63.zip`, `welcome.supp0v3.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33017`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `fd67c956bf8548b7b2cc23bb3774ff0c`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
