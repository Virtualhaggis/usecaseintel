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


The supply chain attack affects those who downloaded installers from the official website between May 6 and May 7, 2026 via the Windows "Download Alternat…

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
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1553.002** — Subvert Trust Controls: Code Signing
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] JDownloader supply-chain C2 callback to parkspringshotel/auraguest/checkinnhotels

`UC_0_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as ua values(Web.user) as user from datamodel=Web where (Web.url="*parkspringshotel.com/m/Lu6aeloo.php*" OR Web.url="*auraguest.lk/m/douV2quu.php*" OR Web.url="*parkspringshotel.com*" OR Web.url="*auraguest.lk*" OR Web.url="*checkinnhotels.com*") by Web.src, Web.dest, Web.site | `drop_dm_object_name(Web)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where (DNS.query="parkspringshotel.com" OR DNS.query="*.parkspringshotel.com" OR DNS.query="auraguest.lk" OR DNS.query="*.auraguest.lk" OR DNS.query="checkinnhotels.com" OR DNS.query="*.checkinnhotels.com") by DNS.src | `drop_dm_object_name(DNS)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _campaign_hosts = dynamic(["parkspringshotel.com","auraguest.lk","checkinnhotels.com"]);
let _campaign_paths = dynamic(["/m/Lu6aeloo.php","/m/douV2quu.php"]);
let _net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has_any (_campaign_hosts) or RemoteUrl has_any (_campaign_paths))
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              ParentProc=InitiatingProcessParentFileName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteIP, RemotePort, RemoteUrl, ActionType;
let _dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q has_any (_campaign_hosts)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              ParentProc=InitiatingProcessParentFileName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              RemoteUrl=Q, RemoteIP="", RemotePort=int(0), ActionType;
union _net, _dns
| order by Timestamp desc
```

### [LLM] JDownloader Windows installer signed/published as Zipline LLC or The Water Team (not AppWork GmbH)

`UC_0_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name values(Processes.process) as process values(Processes.process_hash) as hash values(Processes.process_company) as company values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="JDownloader*.exe" OR Processes.process="*\\JDownloader*.exe*" OR Processes.parent_process_name="JDownloader*.exe") AND (Processes.process_company IN ("Zipline LLC","The Water Team") OR Processes.process_signer IN ("Zipline LLC","The Water Team") OR (Processes.process_company!="AppWork GmbH" AND Processes.process_company!="")) by Processes.dest, Processes.user, Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _bad_company = dynamic(["zipline llc","the water team"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName matches regex @"(?i)^jdownloader.*\.exe$"
     or InitiatingProcessFileName matches regex @"(?i)^jdownloader.*\.exe$"
     or FolderPath has "JDownloader"
     or InitiatingProcessFolderPath has "JDownloader")
| extend CompanyLower = tolower(ProcessVersionInfoCompanyName),
         InitCompanyLower = tolower(InitiatingProcessVersionInfoCompanyName)
| where CompanyLower in (_bad_company)
     or InitCompanyLower in (_bad_company)
     or (isnotempty(CompanyLower) and CompanyLower != "appwork gmbh")
     or (isnotempty(InitCompanyLower) and InitCompanyLower != "appwork gmbh"
         and FileName matches regex @"(?i)^jdownloader.*\.exe$")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, SHA256,
          ProcessVersionInfoCompanyName, ProcessVersionInfoProductName,
          ProcessVersionInfoOriginalFileName,
          InitiatingProcessFileName, InitiatingProcessVersionInfoCompanyName
| order by Timestamp desc
```

### [LLM] JDownloader Linux installer persistence chain (systemd-exec SUID + /etc/profile.d/systemd.sh + /root/.local/share/.pkg)

`UC_0_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.user) as user values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/profile.d/systemd.sh" OR Filesystem.file_path="/root/.local/share/.pkg" OR Filesystem.file_path="/usr/bin/systemd-exec" OR (Filesystem.file_path="/usr/bin/*" AND Filesystem.file_name="systemd-exec") OR (Filesystem.file_path="/etc/profile.d/*" AND Filesystem.file_name="systemd.sh")) AND Filesystem.action IN ("created","modified","renamed","written") by Filesystem.dest | `drop_dm_object_name(Filesystem)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where (Processes.process="*chmod*4755*/usr/bin/systemd-exec*" OR Processes.process="*chmod*u+s*/usr/bin/systemd-exec*" OR Processes.process="*/usr/libexec/upowerd*" OR Processes.process="*/root/.local/share/.pkg*") by Processes.dest, Processes.user | `drop_dm_object_name(Processes)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _bad_paths = dynamic([
    "/etc/profile.d/systemd.sh",
    "/root/.local/share/.pkg",
    "/usr/bin/systemd-exec"
]);
let _file_hits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where FolderPath in (_bad_paths)
         or strcat(FolderPath, FileName) in (_bad_paths)
         or (FolderPath == "/etc/profile.d" and FileName == "systemd.sh")
         or (FolderPath == "/root/.local/share" and FileName == ".pkg")
         or (FolderPath == "/usr/bin"          and FileName == "systemd-exec")
    | project Timestamp, DeviceName, ActionType, Path=strcat(FolderPath,"/",FileName),
              SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, Source="DeviceFileEvents";
let _proc_hits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any (
        "/etc/profile.d/systemd.sh",
        "/root/.local/share/.pkg",
        "/usr/bin/systemd-exec",
        "/usr/libexec/upowerd")
       or (ProcessCommandLine has "chmod" and ProcessCommandLine has "systemd-exec"
           and (ProcessCommandLine has "4755" or ProcessCommandLine has "u+s"))
       or (FileName == "upowerd" and FolderPath != "/usr/libexec")
    | project Timestamp, DeviceName, ActionType="ProcessCreate",
              Path=FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine,
              InitiatingProcessAccountName=AccountName, Source="DeviceProcessEvents";
union _file_hits, _proc_hits
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

`UC_0_4` · phase: **install** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
