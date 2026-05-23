# [CRIT] A rigged game: ScarCruft compromises gaming platform in a supply-chain attack

**Source:** ESET WeLiveSecurity
**Published:** 2026-05-05
**Article:** https://www.welivesecurity.com/en/eset-research/rigged-game-scarcruft-compromises-gaming-platform-supply-chain-attack/

## Threat Profile

A rigged game: ScarCruft compromises gaming platform in a supply-chain attack 
ESET Research
A rigged game: ScarCruft compromises gaming platform in a supply-chain attack ESET researchers have investigated an ongoing attack by the ScarCruft APT group that targets the Yanbian region via backdoor-laced Windows and Android games
Filip Jurčacko 
05 May 2026 
 •  
, 
18 min. read 
ESET researchers uncovered a multiplatform supply-chain attack by North Korea-aligned APT group ScarCruft, targeting the …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sqgame.net`
- **Domain (defanged):** `sqgame.com.cn`
- **Domain (defanged):** `xiazai.sqgame.com.cn`
- **SHA1:** `03E3ECE9F48CF4104AAFC535790CA2FB3C6B26CF`
- **SHA1:** `FC0C691DB7E2D2BD3B0B4C1E24D18DF72168B7D9`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.002** — Exfiltration to Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ScarCruft sqgame supply-chain delivery domain contact (BirdCall/RokRAT)

`UC_250_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("sqgame.net","*.sqgame.net","sqgame.com.cn","*.sqgame.com.cn","xiazai.sqgame.com.cn") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SqgameDomains = dynamic(["sqgame.net","sqgame.com.cn","xiazai.sqgame.com.cn"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (SqgameDomains)
   or tostring(parse_url(RemoteUrl).Host) has_any (SqgameDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] BirdCall trojanized APK/mono.dll SHA1 match on Windows endpoints

`UC_250_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("03E3ECE9F48CF4104AAFC535790CA2FB3C6B26CF","FC0C691DB7E2D2BD3B0B4C1E24D18DF72168B7D9") OR Filesystem.file_name IN ("ybht.apk","sqybhs.apk","20240429.zip") OR (Filesystem.file_name="mono.dll" AND Filesystem.file_path="*sqgame*")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadSha1 = dynamic(["03E3ECE9F48CF4104AAFC535790CA2FB3C6B26CF","FC0C691DB7E2D2BD3B0B4C1E24D18DF72168B7D9"]);
let BadNames = dynamic(["ybht.apk","sqybhs.apk","20240429.zip"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 in~ (BadSha1)
   or FileName in~ (BadNames)
   or (FileName =~ "mono.dll" and FolderPath has "sqgame")
   or FileOriginUrl has_any ("sqgame.net","sqgame.com.cn","xiazai.sqgame.com.cn")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] BirdCall RokRAT cloud-storage C2 beacon (Dropbox/pCloud) from non-browser process

`UC_250_9` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest IN ("*dropboxapi.com","*api.pcloud.com","*pcloud.com","*dropbox.com") AND NOT All_Traffic.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","safari.exe","Dropbox.exe","pCloud.exe","explorer.exe","OneDrive.exe") by All_Traffic.src All_Traffic.dest All_Traffic.process_name All_Traffic.process_path All_Traffic.user | `drop_dm_object_name(All_Traffic)` | where count > 3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CloudC2 = dynamic(["api.dropboxapi.com","content.dropboxapi.com","api.pcloud.com","eapi.pcloud.com","api.pcloud.link"]);
let KnownClients = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","Dropbox.exe","DropboxUpdate.exe","pCloud.exe","OneDrive.exe","explorer.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (CloudC2) or tostring(parse_url(RemoteUrl).Host) has_any (CloudC2)
| where InitiatingProcessFileName !in~ (KnownClients)
| where InitiatingProcessAccountName !endswith "$"
| summarize EventCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Urls=make_set(RemoteUrl,10) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where EventCount >= 3
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

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — A rigged game: ScarCruft compromises gaming platform in a supply-chain attack

`UC_250_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A rigged game: ScarCruft compromises gaming platform in a supply-chain attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("mono.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("mono.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A rigged game: ScarCruft compromises gaming platform in a supply-chain attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("mono.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("mono.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sqgame.net`, `sqgame.com.cn`, `xiazai.sqgame.com.cn`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `03E3ECE9F48CF4104AAFC535790CA2FB3C6B26CF`, `FC0C691DB7E2D2BD3B0B4C1E24D18DF72168B7D9`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
