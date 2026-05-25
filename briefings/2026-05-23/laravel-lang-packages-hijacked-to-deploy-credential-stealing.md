# [HIGH] Laravel Lang packages hijacked to deploy credential-stealing malware

**Source:** BleepingComputer
**Published:** 2026-05-23
**Article:** https://www.bleepingcomputer.com/news/security/laravel-lang-packages-hijacked-to-deploy-credential-stealing-malware/

## Threat Profile

Laravel Lang packages hijacked to deploy credential-stealing malware 
By Lawrence Abrams 
May 23, 2026
04:48 PM
0 
A supply chain attack targeting the Laravel Lang localization packages has exposed developers to a sophisticated credential-stealing malware campaign after attackers abused GitHub version tags to distribute malicious code through Composer packages.
Security firms StepSecurity , Aikido Security , and Socket warned about the compromise on Friday, warning that attackers had rewritten G…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `flipboxstudio.info`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1041** — Exfiltration Over C2 Channel
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1140** — Deobfuscate/Decode Files or Information
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1505.001** — Server Software Component: SQL Stored Procedures
- **T1059.004** — Command and Scripting Interpreter
- **T1199** — Trusted Relationship
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] C2 callback to Laravel Lang stealer infrastructure (flipboxstudio.info)

`UC_13_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where Network_Resolution.query="*flipboxstudio.info*" by Network_Resolution.src, Network_Resolution.query, Network_Resolution.answer | `drop_dm_object_name(Network_Resolution)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count from datamodel=Web where Web.url="*flipboxstudio.info*" OR Web.dest="*flipboxstudio.info*" by Web.src, Web.user, Web.url, Web.dest, Web.http_method | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "flipboxstudio.info" or RemoteUrl endswith ".flipboxstudio.info"
    | project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName),
  (DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where RemoteUrl has "flipboxstudio.info" or AdditionalFields has "flipboxstudio.info"
    | project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] PHP / Composer spawns executable from %TEMP% (DebugElevator dropper)

`UC_13_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="php.exe" OR Processes.parent_process_name="php-cgi.exe") AND (Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\Windows\\Temp\\*") AND Processes.process_name="*.exe" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process_path, Processes.process, Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("php.exe", "php-cgi.exe")
| where FolderPath has @"\AppData\Local\Temp\" or FolderPath has @"\Windows\Temp\"
| where FileName endswith ".exe"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildName   = FileName,
          ChildCmd    = ProcessCommandLine,
          SHA256, MD5
| order by Timestamp desc
```

### [LLM] Malicious helpers.php dropped under vendor/laravel-lang/ during Composer install

`UC_13_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND (Filesystem.file_path="*\\vendor\\laravel-lang\\*" OR Filesystem.file_path="*/vendor/laravel-lang/*") AND Filesystem.file_name="helpers.php" by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.process_name, Filesystem.process_path, Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (FolderPath has @"\vendor\laravel-lang\" or FolderPath has "/vendor/laravel-lang/")
| where FileName =~ "helpers.php"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Composer command line installing or updating laravel-lang/* packages (scope hunt)

`UC_13_8` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="composer*" OR Processes.process_name="php.exe" OR Processes.process="*composer.phar*") AND Processes.process="*laravel-lang*" by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name, Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where (FileName =~ "composer" or FileName =~ "composer.phar" or FileName =~ "composer.bat"
         or ProcessCommandLine has "composer.phar"
         or (InitiatingProcessFileName =~ "php.exe" and ProcessCommandLine has "composer"))
| where ProcessCommandLine has "laravel-lang"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Hits = count(),
            Cmds = make_set(ProcessCommandLine, 25)
            by DeviceName, AccountName
| order by LastSeen desc
```

### [LLM] Chromium Local State / Login Data accessed by non-browser binary from %TEMP% (App-Bound Encryption theft)

`UC_13_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Google\\Chrome\\User Data\\Local State" OR Filesystem.file_path="*\\BraveSoftware\\Brave-Browser\\User Data\\Local State" OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data\\Local State" OR Filesystem.file_name="Login Data" OR Filesystem.file_name="Login Data.tmp") by Filesystem.dest, Filesystem.process_name, Filesystem.process_path, Filesystem.file_path, Filesystem.file_name, Filesystem.action | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("chrome.exe","brave.exe","msedge.exe","msedgewebview2.exe","elevation_service.exe","GoogleUpdate.exe","MicrosoftEdgeUpdate.exe") | search (process_path="*\\AppData\\Local\\Temp\\*" OR process_path="*\\Windows\\Temp\\*" OR process_path="*\\ProgramData\\*" OR process_path="*\\Users\\Public\\*") | stats values(process_name) as procs, values(file_path) as files, count by dest
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCopied", "FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (@"\Google\Chrome\User Data\",
                            @"\BraveSoftware\Brave-Browser\User Data\",
                            @"\Microsoft\Edge\User Data\")
   or PreviousFolderPath has_any (@"\Google\Chrome\User Data\",
                                  @"\BraveSoftware\Brave-Browser\User Data\",
                                  @"\Microsoft\Edge\User Data\")
| where (FileName in~ ("Local State", "Login Data", "Login Data.tmp", "Cookies", "Web Data"))
     or (PreviousFileName in~ ("Local State", "Login Data", "Cookies", "Web Data"))
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "brave.exe",
                                        "msedgewebview2.exe", "googleupdate.exe",
                                        "microsoftedgeupdate.exe", "elevation_service.exe",
                                        "setup.exe", "chrmstp.exe")
| where InitiatingProcessFolderPath has_any (@"\AppData\Local\Temp\",
                                              @"\Windows\Temp\",
                                              @"\ProgramData\",
                                              @"\Users\Public\")
   or InitiatingProcessParentFileName in~ ("php.exe", "php-cgi.exe")
| project Timestamp, DeviceName,
          InitiatingProcessAccountName,
          ActionType, FolderPath, FileName, PreviousFolderPath, PreviousFileName,
          InitiatingProcessFolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          InitiatingProcessSHA256
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

### Article-specific behavioural hunt — Laravel Lang packages hijacked to deploy credential-stealing malware

`UC_13_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Laravel Lang packages hijacked to deploy credential-stealing malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_path="*C:\Users\Mero\OneDrive\Desktop\stuff\claude\Chromium-DebugElevator\x64\Release\DebugChromium.pdb*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Mero\OneDrive\Desktop\stuff\claude\Chromium-DebugElevator\x64\Release\DebugChromium.pdb*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Laravel Lang packages hijacked to deploy credential-stealing malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath has_any ("C:\Users\Mero\OneDrive\Desktop\stuff\claude\Chromium-DebugElevator\x64\Release\DebugChromium.pdb"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Mero\OneDrive\Desktop\stuff\claude\Chromium-DebugElevator\x64\Release\DebugChromium.pdb"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `flipboxstudio.info`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
