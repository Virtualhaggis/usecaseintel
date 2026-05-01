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
- **Domain (defanged):** `www.scoringmnmathleague.org`
- **Domain (defanged):** `coralsunmarine.com`
- **Domain (defanged):** `kazitradebd.com`
- **Domain (defanged):** `oldlinewoodwork.com`
- **Domain (defanged):** `www.mnmathleague.org`
- **Domain (defanged):** `pierregems.com`
- **Domain (defanged):** `www.scgestor.com.br`
- **Domain (defanged):** `galaterrace.com`
- **Domain (defanged):** `ecudecode.mx`
- **Domain (defanged):** `www.anvil.org.ph`
- **Domain (defanged):** `partnerls.pl`
- **Domain (defanged):** `co.uk`
- **Domain (defanged):** `com.ar`
- **Domain (defanged):** `mediostresbarbas.com.ar`
- **Domain (defanged):** `www.bandarpowder.com`
- **Domain (defanged):** `spaincaramoon.com`
- **SHA1:** `03D9B8F0FCF9173D2964CE7173D21E681DFA8DA4`

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
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1584.006** — Compromise Infrastructure: Web Services
- **T1102** — Web Service
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Lazarus DreamJob: wksprt.exe DLL side-loading of DroneEXEHijackingLoader / fake Webservices.dll

`UC_306_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as path values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.process_name="wksprt.exe" AND NOT (Processes.process_path IN ("*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*","*\\Windows\\WinSxS\\*")) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspectWksprt = DeviceProcessEvents
| where FileName =~ "wksprt.exe"
| where FolderPath !startswith @"C:\Windows\System32"
   and FolderPath !startswith @"C:\Windows\SysWOW64"
   and FolderPath !startswith @"C:\Windows\WinSxS"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine;
let sideloadedDll = DeviceImageLoadEvents
| where InitiatingProcessFileName =~ "wksprt.exe"
| where FileName endswith ".dll"
| where FolderPath !startswith @"C:\Windows\System32"
   and FolderPath !startswith @"C:\Windows\SysWOW64"
   and FolderPath !startswith @"C:\Windows\WinSxS"
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath;
union suspectWksprt, sideloadedDll
| sort by Timestamp desc
```

### [LLM] ScoringMathTea / BinMergeLoader C2 callouts to Operation DreamJob 2025 infrastructure

`UC_306_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("23.111.133.162","104.21.80.1","70.32.24.131","185.148.129.24","66.29.144.75","108.181.92.71","104.247.162.67","193.39.187.165","www.scoringmnmathleague.org","coralsunmarine.com","kazitradebd.com","oldlinewoodwork.com","www.mnmathleague.org","pierregems.com","www.scgestor.com.br","galaterrace.com") OR All_Traffic.dest_ip IN ("23.111.133.162","104.21.80.1","70.32.24.131","185.148.129.24","66.29.144.75","108.181.92.71","104.247.162.67","193.39.187.165")) by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let dreamjob_ips = dynamic(["23.111.133.162","104.21.80.1","70.32.24.131","185.148.129.24","66.29.144.75","108.181.92.71","104.247.162.67","193.39.187.165"]);
let dreamjob_domains = dynamic(["www.scoringmnmathleague.org","coralsunmarine.com","kazitradebd.com","oldlinewoodwork.com","www.mnmathleague.org","pierregems.com","www.scgestor.com.br","galaterrace.com"]);
DeviceNetworkEvents
| where RemoteIP in (dreamjob_ips)
   or RemoteUrl has_any (dreamjob_domains)
   or tostring(parse_url(RemoteUrl).Host) in~ (dreamjob_domains)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA1, InitiatingProcessAccountName
| sort by Timestamp desc
```

### [LLM] Trojanized OSS plugin/loader artifacts (ComparePlus, NPPHexEditor, WinMerge, MuPDF, libpcre, dinput) outside install paths

`UC_306_8` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.file_hash) as hashes values(Filesystem.user) as users from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("ComparePlus.dll","NPPHexEditor.dll","DisplayBinaryFiles.dll","HideFirstLetter.dll","DroneEXEHijackingLoader.dll","dinput.dll","pcre.dll","libpcre.dll","SampleIMESimplifiedQuanPin.txt") OR Filesystem.file_hash="03d9b8f0fcf9173d2964ce7173d21e681dfa8da4") AND NOT (Filesystem.file_path IN ("*\\Notepad++\\plugins\\*","*\\WinMerge\\MergePlugins\\*","*\\Program Files*\\TightVNC\\*","*\\Program Files*\\MuPDF\\*","*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*")) by Filesystem.dest Filesystem.file_name Filesystem.file_create_time | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let known_artifacts = dynamic(["ComparePlus.dll","NPPHexEditor.dll","DisplayBinaryFiles.dll","HideFirstLetter.dll","DroneEXEHijackingLoader.dll","SampleIMESimplifiedQuanPin.txt"]);
let legit_paths = dynamic([@"\Notepad++\plugins\", @"\WinMerge\MergePlugins\", @"\Program Files\TightVNC\", @"\Program Files (x86)\TightVNC\", @"\Program Files\MuPDF\", @"\Windows\System32\", @"\Windows\SysWOW64\"]);
DeviceFileEvents
| where SHA1 =~ "03d9b8f0fcf9173d2964ce7173d21e681dfa8da4"
   or FileName in~ (known_artifacts)
   or (FileName endswith "pcre.dll" and FolderPath !startswith @"C:\Program Files")
| where not(FolderPath has_any (legit_paths))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RequestAccountName
| union (
DeviceImageLoadEvents
| where SHA1 =~ "03d9b8f0fcf9173d2964ce7173d21e681dfa8da4"
   or FileName in~ (known_artifacts)
| where not(FolderPath has_any (legit_paths))
| project Timestamp, DeviceName, ActionType="ImageLoad", FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RequestAccountName="")
| sort by Timestamp desc
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — Gotta fly: Lazarus targets the UAV sector

`UC_306_5` · phase: **exploit** · confidence: **High**

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
  - IP / domain IOC(s): `23.111.133.162`, `104.21.80.1`, `70.32.24.131`, `185.148.129.24`, `66.29.144.75`, `108.181.92.71`, `104.247.162.67`, `193.39.187.165` _(+22 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `03D9B8F0FCF9173D2964CE7173D21E681DFA8DA4`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
