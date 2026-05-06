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

- **IPv4 (defanged):** `39.106.249.68`
- **IPv4 (defanged):** `211.239.117.117`
- **IPv4 (defanged):** `114.108.128.157`
- **IPv4 (defanged):** `221.143.43.214`
- **IPv4 (defanged):** `222.231.2.20`
- **IPv4 (defanged):** `222.231.2.23`
- **IPv4 (defanged):** `222.231.2.41`
- **Domain (defanged):** `www.sqgame.net`
- **Domain (defanged):** `xiazai.sqgame.com.cn`
- **Domain (defanged):** `zohomail.com`
- **Domain (defanged):** `ipinfo.io`
- **Domain (defanged):** `sqgame.com.cn`
- **Domain (defanged):** `1980food.co.kr`
- **Domain (defanged):** `inodea.com`
- **Domain (defanged):** `www.lawwell.co.kr`
- **Domain (defanged):** `colorncopy.co.kr`
- **Domain (defanged):** `swr.co.kr`
- **Domain (defanged):** `sejonghaeun.com`
- **Domain (defanged):** `cndsoft.co.kr`
- **SHA1:** `B06110E0FEB7592872E380B7E3B8F77D80DD1108`
- **MD5:** `A8FE823D451D636D0A0366C0629EF5C3`

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
- **T1554** — Compromise Client Software Binary
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1102** — Web Service
- **T1584.004** — Compromise Infrastructure: Server
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ScarCruft sqgame supply-chain — download from xiazai.sqgame.com.cn / sqgame.com.cn

`UC_50_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method values(Web.http_user_agent) as user_agent values(Web.bytes_in) as bytes_in from datamodel=Web where (Web.url="*xiazai.sqgame.com.cn/dating/*.zip" OR Web.dest IN ("xiazai.sqgame.com.cn","sqgame.com.cn","www.sqgame.net","sqgame.net") OR Web.url="*sqgame.com.cn/ybht.apk*" OR Web.url="*sqgame.com.cn/sqybhs.apk*") by host, Web.src, Web.dest, Web.user | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("xiazai.sqgame.com.cn","sqgame.com.cn","sqgame.net")
    or RemoteUrl matches regex @"(?i)xiazai\.sqgame\.com\.cn/dating/\d+\.zip"
    or RemoteUrl has_any ("/ybht.apk","/sqybhs.apk")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, EventTable="Network"),
(DeviceFileEvents
| where Timestamp > ago(30d)
| where FileOriginUrl has_any ("xiazai.sqgame.com.cn","sqgame.com.cn","sqgame.net")
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
          FileOriginUrl, FileOriginIP,
          InitiatingProcessFileName, InitiatingProcessAccountName,
          RemoteUrl=FileOriginUrl, RemoteIP=tostring(FileOriginIP), RemotePort=int(null),
          InitiatingProcessFolderPath, InitiatingProcessCommandLine, EventTable="File")
| order by Timestamp desc
```

### [LLM] Trojanized sqgame mono.dll / BirdCall APK hash hit on Windows endpoint

`UC_50_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("B06110E0FEB7592872E380B7E3B8F77D80DD1108","03E3ECE9F48CF4104AAFC535790CA2FB3C6B26CF","FC0C691DB7E2D2BD3B0B4C1E24D18DF72168B7D9") OR Filesystem.file_name IN ("mono.dll","ybht.apk","sqybhs.apk") by host, Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | where file_name!="mono.dll" OR (file_name="mono.dll" AND match(file_path,"(?i)sqgame"))
```

**Defender KQL:**
```kql
let scarcruft_sha1 = dynamic(["B06110E0FEB7592872E380B7E3B8F77D80DD1108","03E3ECE9F48CF4104AAFC535790CA2FB3C6B26CF","FC0C691DB7E2D2BD3B0B4C1E24D18DF72168B7D9"]);
union
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (scarcruft_sha1)
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256,
            FileOriginUrl, InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessAccountName, EvidenceTable="FileEvents" ),
( DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (scarcruft_sha1)
     or (FileName =~ "mono.dll" and FolderPath has "sqgame" and SHA1 == "B06110E0FEB7592872E380B7E3B8F77D80DD1108")
  | project Timestamp, DeviceName, ActionType="ImageLoaded", FileName, FolderPath, SHA1, SHA256,
            FileOriginUrl="", InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessAccountName=InitiatingProcessAccountName,
            EvidenceTable="ImageLoad" ),
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (scarcruft_sha1) or InitiatingProcessSHA1 in (scarcruft_sha1)
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256,
            FileOriginUrl="", InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessAccountName, EvidenceTable="ProcessEvents" )
| order by Timestamp desc
```

### [LLM] ScarCruft second-stage staging — connection to compromised KR sites or BirdCall C2 IPs

`UC_50_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process_name) as process from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("1980food.co.kr","www.1980food.co.kr","inodea.com","www.inodea.com","lawwell.co.kr","www.lawwell.co.kr","39.106.249.68","211.239.117.117","114.108.128.157","221.143.43.214","222.231.2.20","222.231.2.23","222.231.2.41") by host, All_Traffic.src, All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let scarcruft_hosts = dynamic(["1980food.co.kr","www.1980food.co.kr","inodea.com","www.inodea.com","lawwell.co.kr","www.lawwell.co.kr"]);
let scarcruft_ips   = dynamic(["39.106.249.68","211.239.117.117","114.108.128.157","221.143.43.214","222.231.2.20","222.231.2.23","222.231.2.41"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (scarcruft_ips)
   or RemoteUrl has_any (scarcruft_hosts)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessSHA1, InitiatingProcessSHA256,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| extend SqgameClientHit = iif(InitiatingProcessFolderPath has "sqgame" or InitiatingProcessFileName has "sqgame", "YES", "")
| order by SqgameClientHit desc, Timestamp desc
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

`UC_50_6` · phase: **exploit** · confidence: **High**

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
  - IP / domain IOC(s): `39.106.249.68`, `211.239.117.117`, `114.108.128.157`, `221.143.43.214`, `222.231.2.20`, `222.231.2.23`, `222.231.2.41`, `www.sqgame.net` _(+11 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `B06110E0FEB7592872E380B7E3B8F77D80DD1108`, `A8FE823D451D636D0A0366C0629EF5C3`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
