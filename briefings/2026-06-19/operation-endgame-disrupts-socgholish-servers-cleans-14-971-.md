# [CRIT] Operation Endgame Disrupts SocGholish Servers, Cleans 14,971 WordPress Sites

**Source:** The Hacker News
**Published:** 2026-06-19
**Article:** https://thehackernews.com/2026/06/operation-endgame-disrupts-socgholish.html

## Threat Profile

Operation Endgame Disrupts SocGholish Servers, Cleans 14,971 WordPress Sites 
 Ravie Lakshmanan  Jun 19, 2026 Malware / Threat Intelligence 
Dutch law enforcement authorities, along with counterparts from Canada , Germany, and the U.S., have disrupted malicious infrastructure associated with SocGholish and cleaned up nearly 15,000 infected WordPress websites.
"With these actions we deprive cybercriminals of access to infected computer systems," Maikel Rollman of the Netherlands National High T…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — Malicious File
- **T1059.007** — JavaScript
- **T1189** — Drive-by Compromise
- **T1059.001** — PowerShell
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Web Protocols
- **T1505.003** — Web Shell
- **T1190** — Exploit Public-Facing Application
- **T1546** — Event Triggered Execution
- **T1583.001** — Domains
- **T1071.004** — DNS
- **T1568** — Dynamic Resolution
- **T1136.001** — Local Account
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SocGholish fake-update JS executed by wscript.exe from browser download path

`UC_12_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe") AND Processes.process_name IN ("wscript.exe","cscript.exe") AND (Processes.process="*.js*" OR Processes.process="*.jse*" OR Processes.process="*.wsf*") AND (Processes.process="*Downloads*" OR Processes.process="*Temp*" OR Processes.process="*AppData*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe")
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".js",".jse",".wsf")
| where ProcessCommandLine has_any ("Downloads","Temp","AppData")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### wscript.exe spawning PowerShell with curl/IRM to .top TLD — SocGholish→MintsLoad

`UC_12_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe") AND (Processes.process="*Invoke-WebRequest*" OR Processes.process="*Invoke-RestMethod*" OR Processes.process="*DownloadString*" OR Processes.process="*BitsTransfer*" OR Processes.process="*curl*" OR Processes.process="*iwr *" OR Processes.process="*irm *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | rex field=process "(?i)\.(?<tld>top|xyz|cyou|click|life|world|shop|fun|space|monster|icu|cfd)\b" | where isnotnull(tld) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest","Invoke-RestMethod","DownloadString","DownloadFile","BitsTransfer","curl ","iwr ","irm ","WebClient")
| where ProcessCommandLine matches regex @"(?i)\.(top|xyz|cyou|click|life|world|shop|fun|space|monster|icu|cfd)\b"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PowerShell spawned by IIS w3wp.exe or php-cgi.exe on a WordPress host

`UC_12_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("w3wp.exe","php-cgi.exe","php.exe","httpd.exe","nginx.exe") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("w3wp.exe","php-cgi.exe","php.exe","httpd.exe","nginx.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Unauthorized write to WordPress wp-content/plugins or wp-admin by web server process

`UC_12_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*wp-content/plugins/*" OR Filesystem.file_path="*wp-content/mu-plugins/*" OR Filesystem.file_path="*wp-admin/*") AND (Filesystem.file_name="*.php" OR Filesystem.file_name="*.js") AND Filesystem.process_name IN ("w3wp.exe","php-cgi.exe","php.exe","httpd.exe","nginx.exe") by Filesystem.dest Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName in~ ("w3wp.exe","php-cgi.exe","php.exe","httpd.exe","nginx.exe")
| where FolderPath has_any ("wp-content/plugins","wp-content/mu-plugins","wp-admin","wp-includes")
| where FileName endswith ".php" or FileName endswith ".js"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256, FileSize
| order by Timestamp desc
```

### First-seen subdomain on an established apex domain (SocGholish domain shadowing)

`UC_12_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where DNS.message_type="QUERY" by DNS.query | `drop_dm_object_name(DNS)` | rex field=query "(?<host>[^\.]+)\.(?<apex>[^\.]+\.[^\.]+)$" | eventstats dc(host) as host_count by apex | where host_count > 10 | join apex [| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where DNS.message_type="QUERY" earliest=-1h by DNS.query | `drop_dm_object_name(DNS)` | rex field=query "(?<host>[^\.]+)\.(?<apex>[^\.]+\.[^\.]+)$"] | where count==1
```

**Defender KQL:**
```kql
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1h))
    | where isnotempty(RemoteUrl)
    | extend Host = tostring(split(RemoteUrl, "/")[0])
    | extend Apex = strcat(tostring(split(Host, ".")[-2]), ".", tostring(split(Host, ".")[-1]))
    | summarize BaselineSubs = dcount(Host), BaselineHits = count() by Apex
    | where BaselineHits > 100 and BaselineSubs >= 1;
let Recent = DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where isnotempty(RemoteUrl)
    | extend Host = tostring(split(RemoteUrl, "/")[0])
    | extend Apex = strcat(tostring(split(Host, ".")[-2]), ".", tostring(split(Host, ".")[-1]))
    | summarize FirstSeen = min(Timestamp), HitsRecent = count(), Devices = dcount(DeviceName) by Apex, Host;
Recent
| join kind=inner Baseline on Apex
| join kind=leftanti (
    DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1h))
    | extend Host = tostring(split(RemoteUrl, "/")[0])
    | summarize by Host
) on Host
| order by FirstSeen desc
```

### Suspicious admin user creation in WordPress wp_users by web server context

`UC_12_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=mysql sourcetype=mysql:audit OR sourcetype=mysql:query ("wp_users" OR "wp_usermeta") ("INSERT" OR "UPDATE") ("administrator" OR "wp_capabilities") | rex field=_raw "(?i)user_login\s*=\s*'(?<new_user>[^']+)'" | stats min(_time) as firstTime values(host) as hosts values(new_user) as new_users by user | where isnotnull(new_user)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName in~ ("w3wp.exe","php-cgi.exe","php.exe")
| where FolderPath has_any ("wp-content/uploads","wp-content/themes")
| where FileName endswith ".php"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("wp_insert_user","administrator","wp_capabilities")
) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 10 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
