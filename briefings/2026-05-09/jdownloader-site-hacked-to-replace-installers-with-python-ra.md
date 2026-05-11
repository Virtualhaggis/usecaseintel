# [HIGH] JDownloader site hacked to replace installers with Python RAT malware

**Source:** BleepingComputer
**Published:** 2026-05-09
**Article:** https://www.bleepingcomputer.com/news/security/jdownloader-site-hacked-to-replace-installers-with-python-rat-malware/

## Threat Profile

JDownloader site hacked to replace installers with Python RAT malware 
By Lawrence Abrams 
May 9, 2026
03:27 PM
0 
The website for the popular JDownloader download manager was compromised earlier this week to distribute malicious Windows and Linux installers, with the Windows payload found deploying a Python-based remote access trojan.
The supply chain attack affects those who downloaded installers from the official website between May 6 and May 7, 2026 via the Windows "Download Alternative Inst…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `parkspringshotel.com`
- **Domain (defanged):** `auraguest.lk`
- **Domain (defanged):** `checkinnhotels.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1027.002** — Obfuscated Files or Information: Software Packing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] JDownloader Supply-Chain RAT C2 Callback (parkspringshotel/auraguest/checkinnhotels)

`UC_8_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*parkspringshotel.com/m/Lu6aeloo.php*" OR Web.url="*auraguest.lk/m/douV2quu.php*" OR Web.dest IN ("parkspringshotel.com","auraguest.lk","checkinnhotels.com") OR Web.url="*checkinnhotels.com/*") by Web.src Web.user Web.dest Web.url Web.http_user_agent Web.action | `drop_dm_object_name(Web)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("parkspringshotel.com","auraguest.lk","checkinnhotels.com") OR DNS.query="*.parkspringshotel.com" OR DNS.query="*.auraguest.lk" OR DNS.query="*.checkinnhotels.com" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let JdC2Domains = dynamic(["parkspringshotel.com","auraguest.lk","checkinnhotels.com"]);
let JdC2UrlFragments = dynamic(["/m/Lu6aeloo.php","/m/douV2quu.php"]);
union
(
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (JdC2Domains) or RemoteUrl has_any (JdC2UrlFragments)
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl, ActionType
),
(
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q in~ (JdC2Domains) or Q endswith ".parkspringshotel.com" or Q endswith ".auraguest.lk" or Q endswith ".checkinnhotels.com"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Query=Q, ActionType
)
| order by Timestamp desc
```

### [LLM] Trojanized JDownloader Installer — Attacker PE Company Strings ('Zipline LLC' / 'The Water Team')

`UC_8_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=1 (Company="Zipline LLC" OR Company="The Water Team") | stats min(_time) as firstTime max(_time) as lastTime values(CommandLine) as cmds values(User) as users values(Hashes) as hashes values(ParentImage) as parents count by Computer Image Company OriginalFileName Product | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TrojanCompanies = dynamic(["Zipline LLC", "The Water Team"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoCompanyName in~ (TrojanCompanies)
   or InitiatingProcessVersionInfoCompanyName in~ (TrojanCompanies)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessVersionInfoOriginalFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessVersionInfoCompanyName
| order by Timestamp desc
```

### [LLM] JDownloader Trojanized Linux Installer — Persistence Footprint and upowerd Masquerade

`UC_8_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/usr/bin/systemd-exec" OR Filesystem.file_path="/etc/profile.d/systemd.sh" OR Filesystem.file_path="/root/.local/share/.pkg") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/usr/libexec/upowerd*" OR Processes.process="*/root/.local/share/.pkg*" OR Processes.process="*/usr/bin/systemd-exec*") AND NOT (Processes.process_path="/usr/libexec/upowerd") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where (FolderPath =~ "/usr/bin/" and FileName =~ "systemd-exec")
       or (FolderPath =~ "/etc/profile.d/" and FileName =~ "systemd.sh")
       or (FolderPath =~ "/root/.local/share/" and FileName =~ ".pkg")
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
),
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "/usr/libexec/upowerd"
    | where not(FolderPath =~ "/usr/libexec/" and FileName =~ "upowerd")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FolderPath =~ "/root/.local/share/" and FileName =~ ".pkg"
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
)
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

### Article-specific behavioural hunt — JDownloader site hacked to replace installers with Python RAT malware

`UC_8_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — JDownloader site hacked to replace installers with Python RAT malware ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/*" OR Filesystem.file_path="*/root/.local/share/.pkg*" OR Filesystem.file_path="*/etc/profile.d/systemd.sh*" OR Filesystem.file_path="*/usr/libexec/upowerd*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — JDownloader site hacked to replace installers with Python RAT malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/", "/root/.local/share/.pkg", "/etc/profile.d/systemd.sh", "/usr/libexec/upowerd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `parkspringshotel.com`, `auraguest.lk`, `checkinnhotels.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
