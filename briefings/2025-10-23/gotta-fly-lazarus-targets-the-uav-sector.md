# [CRIT] Gotta fly: Lazarus targets the UAV sector

**Source:** ESET WeLiveSecurity
**Published:** 2025-10-23
**Article:** https://www.welivesecurity.com/en/eset-research/gotta-fly-lazarus-targets-uav-sector/

## Threat Profile

Gotta fly: Lazarus targets the UAV sector 
ESET Research
Gotta fly: Lazarus targets the UAV sector ESET research analyzes a recent instance of the Operation DreamJob cyberespionage campaign conducted by Lazarus, a North Korea-aligned APT group
Peter Kálnai 
Alexis Rapin 
23 Oct 2025 
 •  
, 
17 min. read 
ESET researchers have recently observed a new instance of Operation DreamJob – a campaign that we track under the umbrella of North Korea-aligned Lazarus – in which several European companies a…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.111.133.162`
- **IPv4 (defanged):** `104.21.80.1`
- **IPv4 (defanged):** `70.32.24.131`
- **IPv4 (defanged):** `185.148.129.24`
- **IPv4 (defanged):** `66.29.144.75`
- **IPv4 (defanged):** `108.181.92.71`
- **IPv4 (defanged):** `104.247.162.67`
- **IPv4 (defanged):** `193.39.187.165`
- **IPv4 (defanged):** `172.67.193.139`
- **IPv4 (defanged):** `77.55.252.111`
- **IPv4 (defanged):** `45.148.29.122`
- **IPv4 (defanged):** `75.102.23.3`
- **IPv4 (defanged):** `152.42.239.211`
- **IPv4 (defanged):** `95.217.119.214`
- **Domain (defanged):** `coralsunmarine.com`
- **Domain (defanged):** `kazitradebd.com`
- **Domain (defanged):** `oldlinewoodwork.com`
- **Domain (defanged):** `mnmathleague.org`
- **Domain (defanged):** `pierregems.com`
- **Domain (defanged):** `scgestor.com.br`
- **Domain (defanged):** `galaterrace.com`
- **Domain (defanged):** `ecudecode.mx`
- **Domain (defanged):** `anvil.org.ph`
- **Domain (defanged):** `partnerls.pl`
- **Domain (defanged):** `trainingpharmacist.co.uk`
- **Domain (defanged):** `mediostresbarbas.com.ar`
- **Domain (defanged):** `bandarpowder.com`
- **Domain (defanged):** `spaincaramoon.com`
- **SHA256:** `c39ecc7d9f1e225a37304345731fffe72cdb95b21aeb06aa6022f6d338777012`
- **SHA256:** `083d4a4ef6267c9a0ab57f1e5a2ed45ff67a0b4db83bbd43563458a223781120`
- **SHA256:** `503b3ece42f540409bcb2f0abc7584e557a0d120b7ba9854b4548496b2546d34`
- **SHA256:** `98d1a10521a4dd968d75e2860e523311b5851737795c84943c380870794c851a`
- **SHA256:** `f9a9c1a13ed74aebca0652b102755833fc084e221d731b5e7ae76ff136f85864`
- **SHA1:** `28978E987BC59E75CA22562924EAB93355CF679E`
- **SHA1:** `5E5BBA521F0034D342CC26DB8BCFECE57DBD4616`
- **SHA1:** `B12EEB595FEEC2CFBF9A60E1CC21A14CE8873539`
- **SHA1:** `26AA2643B07C48CB6943150ADE541580279E8E0E`
- **SHA1:** `0CB73D70FD4132A4FF5493DAA84AAE839F6329D5`
- **SHA1:** `03D9B8F0FCF9173D2964CE7173D21E681DFA8DA4`
- **SHA1:** `71D0DDB7C6CAC4BA2BDE679941FA92A31FBEC1FF`
- **SHA1:** `87B2DF764455164C6982BA9700F27EA34D3565DF`
- **SHA1:** `E670C4275EC24D403E0D4DE7135CBCF1D54FF09C`
- **SHA1:** `5B85DD485FD516AA1F4412801897A40A9BE31837`
- **SHA1:** `B68C49841DC48E3672031795D85ED24F9F619782`
- **SHA1:** `AC16B1BAEDE349E4824335E0993533BF4FC116B3`
- **SHA1:** `2AA341B03FAC3054C57640122EA849BC0C2B6AF6`
- **SHA1:** `CB7834BE7DE07F89352080654F7FEB574B42A2B8`
- **SHA1:** `262B4ED6AC6A977135DECA5B0872B7D6D676083A`
- **SHA1:** `086816466D9D9C12FCADA1C872B8C0FF0A5FC611`
- **SHA1:** `2A2B20FDDD65BA28E7C57AC97A158C15B61A7B05`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1574.002** — DLL Side-Loading
- **T1574.001** — DLL Search Order Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1584.004** — Compromise Infrastructure: Server
- **T1027.009** — Embedded Payloads
- **T1566.002** — Spearphishing Link
- **T1036.005** — Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Lazarus DreamJob DLL side-load: wksprt.exe loading webservices.dll from ProgramData

`UC_715_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="wksprt.exe" OR Processes.process_name="wkspbroker.exe") (Processes.process_path="*\\ProgramData\\EMC\\*" OR Processes.process_path="*\\ProgramData\\Adobe\\*" OR Processes.process_path="*\\AppData\\Roaming\\Microsoft\\RemoteApp\\*" OR Processes.process_path="*\\ProgramData\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | rename firstTime as firstTime_p lastTime as lastTime_p | join type=inner dest [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="webservices.dll" OR Filesystem.file_name="radcui.dll") (Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\RemoteApp\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime_p) ctime(lastTime_p)
```

**Defender KQL:**
```kql
let suspect_paths = dynamic([@"\programdata\emc\", @"\programdata\adobe\", @"\appdata\roaming\microsoft\remoteapp\"]);
let host_proc = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wksprt.exe", "wkspbroker.exe")
| where FolderPath has_any (suspect_paths) or FolderPath !startswith @"C:\Windows\"
| project Timestamp, DeviceId, DeviceName, AccountName, ProcessId = tostring(ProcessId), FileName, FolderPath, ProcessCommandLine, SHA256;
let host_lib = DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("webservices.dll", "radcui.dll", "libmupdf.dll", "libpcre.dll", "hidefirstletter.dll", "tsmsisrv.dll")
| where FolderPath has_any (suspect_paths) or FolderPath !startswith @"C:\Windows\"
| project Timestamp, DeviceId, DllName = FileName, DllPath = FolderPath, DllSha256 = SHA256, InitiatingProcessFileName, InitiatingProcessId = tostring(InitiatingProcessId);
host_proc
| join kind=inner host_lib on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where InitiatingProcessFileName =~ FileName
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, DllName, DllPath, DllSha256, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] ScoringMathTea C2 beacon to compromised WordPress hosts (Lazarus DreamJob IOCs)

`UC_715_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest in ("23.111.133.162","104.21.80.1","70.32.24.131","185.148.129.24","66.29.144.75","108.181.92.71","104.247.162.67","193.39.187.165") OR All_Traffic.dest_host in ("coralsunmarine.com","kazitradebd.com","oldlinewoodwork.com","mnmathleague.org","pierregems.com","scgestor.com.br","galaterrace.com","ecudecode.mx")) by All_Traffic.dest All_Traffic.dest_host All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let c2_domains = dynamic(["coralsunmarine.com","kazitradebd.com","oldlinewoodwork.com","mnmathleague.org","pierregems.com","scgestor.com.br","galaterrace.com","ecudecode.mx"]);
let c2_ips = dynamic(["23.111.133.162","104.21.80.1","70.32.24.131","185.148.129.24","66.29.144.75","108.181.92.71","104.247.162.67","193.39.187.165"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2_ips) or RemoteUrl has_any (c2_domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] Lazarus DreamJob loader/dropper SHA1 sighting (DroneEXEHijackingLoader / NukeSped family)

`UC_715_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.user) as user values(Filesystem.dest) as dest from datamodel=Endpoint.Filesystem where Filesystem.file_hash in ("28978E987BC59E75CA22562924EAB93355CF679E","5E5BBA521F0034D342CC26DB8BCFECE57DBD4616","B12EEB595FEEC2CFBF9A60E1CC21A14CE8873539","26AA2643B07C48CB6943150ADE541580279E8E0E","0CB73D70FD4132A4FF5493DAA84AAE839F6329D5","03D9B8F0FCF9173D2964CE7173D21E681DFA8DA4","71D0DDB7C6CAC4BA2BDE679941FA92A31FBEC1FF","87B2DF764455164C6982BA9700F27EA34D3565DF","c39ecc7d9f1e225a37304345731fffe72cdb95b21aeb06aa6022f6d338777012","083d4a4ef6267c9a0ab57f1e5a2ed45ff67a0b4db83bbd43563458a223781120","503b3ece42f540409bcb2f0abc7584e557a0d120b7ba9854b4548496b2546d34","98d1a10521a4dd968d75e2860e523311b5851737795c84943c380870794c851a","f9a9c1a13ed74aebca0652b102755833fc084e221d731b5e7ae76ff136f85864") by Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let sha1_iocs = dynamic(["28978E987BC59E75CA22562924EAB93355CF679E","5E5BBA521F0034D342CC26DB8BCFECE57DBD4616","B12EEB595FEEC2CFBF9A60E1CC21A14CE8873539","26AA2643B07C48CB6943150ADE541580279E8E0E","0CB73D70FD4132A4FF5493DAA84AAE839F6329D5","03D9B8F0FCF9173D2964CE7173D21E681DFA8DA4","71D0DDB7C6CAC4BA2BDE679941FA92A31FBEC1FF","87B2DF764455164C6982BA9700F27EA34D3565DF"]);
let sha256_iocs = dynamic(["c39ecc7d9f1e225a37304345731fffe72cdb95b21aeb06aa6022f6d338777012","083d4a4ef6267c9a0ab57f1e5a2ed45ff67a0b4db83bbd43563458a223781120","503b3ece42f540409bcb2f0abc7584e557a0d120b7ba9854b4548496b2546d34","98d1a10521a4dd968d75e2860e523311b5851737795c84943c380870794c851a","f9a9c1a13ed74aebca0652b102755833fc084e221d731b5e7ae76ff136f85864"]);
union isfuzzy=true
  (DeviceFileEvents
    | where Timestamp > ago(90d)
    | where SHA1 in (sha1_iocs) or SHA256 in (sha256_iocs)
    | project Timestamp, Source="FileEvents", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceImageLoadEvents
    | where Timestamp > ago(90d)
    | where SHA1 in (sha1_iocs) or SHA256 in (sha256_iocs)
    | project Timestamp, Source="ImageLoad", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine=""),
  (DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where SHA1 in (sha1_iocs) or SHA256 in (sha256_iocs)
    | project Timestamp, Source="ProcessEvents", DeviceName, AccountName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine)
| order by Timestamp desc
```

### [LLM] DreamJob trojanized PDF/installer execution from job-lure decoy folder

`UC_715_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name in ("explorer.exe","7zg.exe","7zfm.exe","winrar.exe","rar.exe","chrome.exe","msedge.exe","firefox.exe","outlook.exe") Processes.process_name in ("wksprt.exe","wkspbroker.exe")) (Processes.process_path="*\\Users\\*\\Downloads\\*" OR Processes.process_path="*\\Users\\*\\Desktop\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\ProgramData\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("wksprt.exe","wkspbroker.exe")
| where InitiatingProcessFileName in~ ("explorer.exe","7zg.exe","7zfm.exe","winrar.exe","rar.exe","chrome.exe","msedge.exe","firefox.exe","outlook.exe","thunderbird.exe")
| where FolderPath has_any (@"\users\", @"\downloads\", @"\desktop\", @"\temp\", @"\programdata\")
| where FolderPath !startswith @"C:\Windows\"
| join kind=inner (
    DeviceImageLoadEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("webservices.dll","radcui.dll","libmupdf.dll","libpcre.dll","hidefirstletter.dll","tsmsisrv.dll")
    | where InitiatingProcessVersionInfoCompanyName !has "Microsoft"
    | project DeviceId, Timestamp_lib=Timestamp, DllName=FileName, DllPath=FolderPath, DllSha256=SHA256, InitiatingProcessId
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ParentExec=InitiatingProcessFileName, ExecPath=FolderPath, DllName, DllPath, DllSha256, ProcessCommandLine
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

### Article-specific behavioural hunt — Gotta fly: Lazarus targets the UAV sector

`UC_715_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Gotta fly: Lazarus targets the UAV sector ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("droneexehijackingloader.dll","dinput.dll","wksprt.exe","wkspbroker.exe","radcui.dll","d3d8.dll","tsmsisrv.dll","libmupdf.dll","libpcre.dll","webservices.dll","msadomr.dll","compareplus.dll") OR Processes.process_path="*E:\Work\Troy\*" OR Processes.process_path="*%APPDATA%\Microsoft\RemoteApp\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*E:\Work\Troy\*" OR Filesystem.file_path="*%APPDATA%\Microsoft\RemoteApp\*" OR Filesystem.file_name IN ("droneexehijackingloader.dll","dinput.dll","wksprt.exe","wkspbroker.exe","radcui.dll","d3d8.dll","tsmsisrv.dll","libmupdf.dll","libpcre.dll","webservices.dll","msadomr.dll","compareplus.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Gotta fly: Lazarus targets the UAV sector
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("droneexehijackingloader.dll", "dinput.dll", "wksprt.exe", "wkspbroker.exe", "radcui.dll", "d3d8.dll", "tsmsisrv.dll", "libmupdf.dll", "libpcre.dll", "webservices.dll", "msadomr.dll", "compareplus.dll") or FolderPath has_any ("E:\Work\Troy\", "%APPDATA%\Microsoft\RemoteApp\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("E:\Work\Troy\", "%APPDATA%\Microsoft\RemoteApp\") or FileName in~ ("droneexehijackingloader.dll", "dinput.dll", "wksprt.exe", "wkspbroker.exe", "radcui.dll", "d3d8.dll", "tsmsisrv.dll", "libmupdf.dll", "libpcre.dll", "webservices.dll", "msadomr.dll", "compareplus.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.111.133.162`, `104.21.80.1`, `70.32.24.131`, `185.148.129.24`, `66.29.144.75`, `108.181.92.71`, `104.247.162.67`, `193.39.187.165` _(+20 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c39ecc7d9f1e225a37304345731fffe72cdb95b21aeb06aa6022f6d338777012`, `083d4a4ef6267c9a0ab57f1e5a2ed45ff67a0b4db83bbd43563458a223781120`, `503b3ece42f540409bcb2f0abc7584e557a0d120b7ba9854b4548496b2546d34`, `98d1a10521a4dd968d75e2860e523311b5851737795c84943c380870794c851a`, `f9a9c1a13ed74aebca0652b102755833fc084e221d731b5e7ae76ff136f85864`, `28978E987BC59E75CA22562924EAB93355CF679E`, `5E5BBA521F0034D342CC26DB8BCFECE57DBD4616`, `B12EEB595FEEC2CFBF9A60E1CC21A14CE8873539` _(+14 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
