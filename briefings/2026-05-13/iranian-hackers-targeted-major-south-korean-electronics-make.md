# [CRIT] Iranian hackers targeted major South Korean electronics maker

**Source:** BleepingComputer
**Published:** 2026-05-13
**Article:** https://www.bleepingcomputer.com/news/security/iranian-hackers-targeted-major-south-korean-electronics-maker/

## Threat Profile

Iranian hackers targeted major South Korean electronics maker 
By Bill Toulas 
May 13, 2026
05:59 PM
0 
The Iran-linked hacking group MuddyWater (a.k.a. Seedworm, Static Kitten) launched a broad cyber-espionage campaign targeting at least nine high-profile organizations across multiple sectors and countries.
Among the victims are a major South Korean electronics manufacturer, government agencies, an international airport in the Middle East, industrial manufacturers in Asia, and educational insti…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1218** — System Binary Proxy Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Seedworm DLL side-load via Fortemedia fmapp.exe / SentinelOne sentinelmemoryscanner.exe

`UC_60_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("fmapp.exe","sentinelmemoryscanner.exe") AND NOT (Processes.process_path IN ("*\\Program Files\\Fortemedia\\*","*\\Program Files (x86)\\Fortemedia\\*","*\\Program Files\\SentinelOne\\*","*\\Program Files (x86)\\SentinelOne\\*","*\\ProgramData\\Sentinel*")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name Processes.parent_process Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("fmapp.exe","sentinelmemoryscanner.exe")
| where FileName in~ ("fmapp.dll","sentinelagentcore.dll")
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Fortemedia\")
    and not(InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\Fortemedia\")
    and not(InitiatingProcessFolderPath startswith @"C:\Program Files\SentinelOne\")
    and not(InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\SentinelOne\")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          ParentBinary = InitiatingProcessFileName,
          ParentPath   = InitiatingProcessFolderPath,
          LoadedDll    = FileName,
          DllPath      = FolderPath,
          DllSHA256    = SHA256,
          ParentSHA256 = InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] Seedworm data exfiltration to sendit.sh file-sharing service

`UC_60_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods sum(Web.bytes_out) as bytes_out from datamodel=Web.Web where (Web.url="*sendit.sh*" OR Web.dest="sendit.sh" OR Web.dest="*.sendit.sh") by Web.src Web.user Web.dest Web.site
| `drop_dm_object_name(Web)`
| where bytes_out > 0
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  ( DeviceNetworkEvents
      | where Timestamp > ago(7d)
      | where RemoteUrl has "sendit.sh" or RemoteUrl endswith ".sendit.sh"
      | project Timestamp, DeviceName, InitiatingProcessAccountName,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                RemoteUrl, RemoteIP, RemotePort, Source = "NetworkEvent" ),
  ( DeviceEvents
      | where Timestamp > ago(7d)
      | where ActionType == "DnsQueryResponse"
      | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
      | where Q has "sendit.sh"
      | project Timestamp, DeviceName, InitiatingProcessAccountName,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                RemoteUrl = Q, RemoteIP = "", RemotePort = int(null), Source = "DnsQuery" )
| order by Timestamp desc
```

### [LLM] Seedworm Node.js loader spawning PowerShell for recon / credential theft

`UC_60_5` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parent_cmdlines from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" AND Processes.process_name IN ("powershell.exe","pwsh.exe") AND NOT Processes.user IN ("*$") AND NOT Processes.parent_process_path IN ("*\\nodejs\\*","*\\AppData\\Roaming\\npm\\*","*\\Program Files\\Microsoft VS Code\\*","*\\.vscode\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name Processes.parent_process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _dev_paths = dynamic([@"\nodejs\", @"\AppData\Roaming\npm\", @"\Microsoft VS Code\", @"\.vscode\", @"\JetBrains\"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName =~ "node.exe"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where not(InitiatingProcessFolderPath has_any (_dev_paths))
| extend SuspectArgs = ProcessCommandLine has_any (
    "-EncodedCommand","-enc ","-e ","-w hidden","-WindowStyle Hidden",
    "DownloadString","IEX","Invoke-Expression","FromBase64String",
    "reg save","HKLM\\SAM","HKLM\\SECURITY","HKLM\\SYSTEM",
    "Get-WmiObject","AntiVirusProduct","Screenshot","netstat","whoami","systeminfo")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          Child       = FileName,
          ChildCmd    = ProcessCommandLine,
          ChildSHA256 = SHA256,
          SuspectArgs
| order by SuspectArgs desc, Timestamp desc
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

### Article-specific behavioural hunt — Iranian hackers targeted major South Korean electronics maker

`UC_60_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Iranian hackers targeted major South Korean electronics maker ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("fmapp.exe","sentinelmemoryscanner.exe","fmapp.dll","sentinelagentcore.dll","node.js","sendit.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("fmapp.exe","sentinelmemoryscanner.exe","fmapp.dll","sentinelagentcore.dll","node.js","sendit.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Iranian hackers targeted major South Korean electronics maker
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("fmapp.exe", "sentinelmemoryscanner.exe", "fmapp.dll", "sentinelagentcore.dll", "node.js", "sendit.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("fmapp.exe", "sentinelmemoryscanner.exe", "fmapp.dll", "sentinelagentcore.dll", "node.js", "sendit.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
