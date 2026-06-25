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
- **T1189** — Drive-by Compromise
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1036.008** — Masquerading: Masquerade File Type
- **T1204.002** — User Execution: Malicious File
- **T1033** — System Owner/User Discovery
- **T1482** — Domain Trust Discovery
- **T1087.002** — Account Discovery: Domain Account
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SocGholish fake-update JavaScript (.js) downloaded by a browser to Downloads/Temp

`UC_77_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.js" (Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_guid 
| `drop_dm_object_name(Filesystem)` 
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
| where FileName endswith ".js"
| where FolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\")
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe")
| where isnotempty(FileOriginUrl)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, SHA256
| order by Timestamp desc
```

### wscript.exe/cscript.exe executing a .js from a user download path (SocGholish execution)

`UC_77_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") (Processes.parent_process_name="explorer.exe" OR Processes.parent_process_name="chrome.exe" OR Processes.parent_process_name="msedge.exe" OR Processes.parent_process_name="firefox.exe" OR Processes.parent_process_name="brave.exe" OR Processes.parent_process_name="opera.exe") Processes.process="*.js*" (Processes.process="*\\Downloads\\*" OR Processes.process="*\\Temp\\*" OR Processes.process="*\\AppData\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash 
| `drop_dm_object_name(Processes)` 
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine contains ".js"
| where ProcessCommandLine has_any (@"\Downloads\", @"\Temp\", @"\AppData\")
| where InitiatingProcessFileName in~ ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### SocGholish host/AD reconnaissance spawned by Windows Script Host

`UC_77_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="cscript.exe") (Processes.process_name="whoami.exe" OR Processes.process_name="net.exe" OR Processes.process_name="net1.exe" OR Processes.process_name="nltest.exe" OR Processes.process_name="systeminfo.exe" OR Processes.process_name="ipconfig.exe" OR Processes.process_name="wmic.exe" OR Processes.process_name="tasklist.exe" OR Processes.process_name="reg.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process 
| `drop_dm_object_name(Processes)` 
| stats values(process_name) as recon_tools values(process) as recon_cmds dc(process_name) as distinct_tools min(firstTime) as firstTime max(lastTime) as lastTime by dest, user, parent_process_name 
| where distinct_tools >= 2 
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where FileName in~ ("whoami.exe","net.exe","net1.exe","nltest.exe","systeminfo.exe","ipconfig.exe","wmic.exe","tasklist.exe","reg.exe","cmd.exe")
| where AccountName !endswith "$"
| summarize ReconTools=make_set(FileName), SampleCmds=make_set(ProcessCommandLine, 8), DistinctTools=dcount(FileName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where DistinctTools >= 2   // SocGholish chains several recon utilities under one WSH parent
| order by LastSeen desc
```

### wscript.exe (spawned by browser) making external network connections — SocGholish C2

`UC_77_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") (Processes.parent_process_name="chrome.exe" OR Processes.parent_process_name="msedge.exe" OR Processes.parent_process_name="firefox.exe" OR Processes.parent_process_name="brave.exe" OR Processes.parent_process_name="opera.exe" OR Processes.parent_process_name="vivaldi.exe") by Processes.dest Processes.process_guid Processes.process_name Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| join type=inner process_guid [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.direction=outbound NOT (All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=172.16.0.0/12 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip=127.0.0.0/8 OR All_Traffic.dest_ip=169.254.0.0/16) by All_Traffic.dest All_Traffic.process_guid All_Traffic.dest_ip All_Traffic.dest_port 
| `drop_dm_object_name(All_Traffic)`] 
| table firstTime, dest, parent_process_name, process_name, dest_ip, dest_port 
| convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where InitiatingProcessParentFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe")
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName !endswith "$"
| summarize Connections=count(), RemoteIPs=make_set(RemoteIP, 20), RemoteUrls=make_set(RemoteUrl, 20), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by LastSeen desc
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

Severity classified as **CRIT** based on: 8 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
