# [HIGH] Police cleans nearly 15,000 SocGholish-infected sites tied to Evil Corp

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/law-enforcement-nukes-socgholish-malware-from-nearly-15-000-sites/

## Threat Profile

Police cleans nearly 15,000 SocGholish-infected sites tied to Evil Corp 
By Sergiu Gatlan 
June 18, 2026
09:25 AM
0 


International law enforcement agencies cleaned nearly 15,000 malware-infected WordPress websites and took down more than 100 servers linked to the SocGholish botnet and the Evil Corp Russian cybercrime group.


This joint action (supported by Europol and Eurojust) was part of Operation Endgame , a major law enforcement operation now aimed at disrupting a key infection chain …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1189** — Drive-by Compromise
- **T1584.006** — Compromise Infrastructure: Web Services
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake browser update JavaScript spawned from browser download directory (SocGholish)

`UC_0_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") AND Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe") AND (Processes.process LIKE "%Update.js%" OR Processes.process LIKE "%Chrome_Update%" OR Processes.process LIKE "%Firefox_Update%" OR Processes.process LIKE "%BrowserUpdate%" OR Processes.process LIKE "%.js%") AND (Processes.process LIKE "%\\Downloads\\%" OR Processes.process LIKE "%\\Temp\\%" OR Processes.process LIKE "%\\AppData\\Local\\Temp%") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("wscript.exe","cscript.exe")
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| where ProcessCommandLine has ".js"
| where ProcessCommandLine has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\")
   or ProcessCommandLine has_any ("Update.js","Chrome_Update","Firefox_Update","BrowserUpdate","Edge_Update")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Script interpreter outbound HTTPS within 60s of Update.js execution (SocGholish)

`UC_0_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as scriptTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") AND Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe") AND Processes.process LIKE "%.js%" by Processes.dest Processes.user Processes.process_id Processes.process | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats `summariesonly` count min(_time) as netTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port=443 OR All_Traffic.dest_port=80) AND All_Traffic.app IN ("wscript.exe","cscript.exe","powershell.exe") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | rename All_Traffic.src as dest All_Traffic.dest as remote_ip All_Traffic.dest_port as remote_port All_Traffic.app as net_proc] | eval delta=netTime-scriptTime | where delta>=0 AND delta<=60 | table scriptTime netTime delta dest user process net_proc remote_ip remote_port
```

**Defender KQL:**
```kql
let Window = 60s;
let Scripts = DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where AccountName !endswith "$"
  | where FileName in~ ("wscript.exe","cscript.exe")
  | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe")
  | where ProcessCommandLine has ".js"
  | project ScriptTime = Timestamp, DeviceId, DeviceName, AccountName, ScriptCmd = ProcessCommandLine, ScriptPid = ProcessId;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","powershell.exe","pwsh.exe")
| where RemoteIPType == "Public"
| where RemotePort in (443, 80)
| join kind=inner Scripts on DeviceId
| where Timestamp between (ScriptTime .. ScriptTime + Window)
| project ScriptTime, NetTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ScriptTime),
          DeviceName, AccountName, ScriptCmd,
          NetProc = InitiatingProcessFileName,
          NetCmd = InitiatingProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort
| order by ScriptTime desc
```

### WordPress site serving injected SocGholish loader to internal browser

`UC_0_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url LIKE "%/wp-content/%" OR Web.url LIKE "%/wp-includes/%" OR Web.url LIKE "%/wp-admin/%" OR Web.url LIKE "%/wp-json/%" by Web.src Web.user Web.url Web.url_domain Web.http_user_agent Web.http_referrer Web.http_content_type | `drop_dm_object_name(Web)` | where like(url, "%.js%") AND (like(http_content_type, "%javascript%") OR like(http_content_type, "%text/html%")) | stats count dc(src) as host_count values(url) as urls by url_domain | where host_count >= 1
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| where RemoteUrl has_any ("/wp-content/","/wp-includes/","/wp-admin/admin-ajax.php","/wp-json/")
| where RemoteUrl endswith ".js" or RemoteUrl has ".js?" or RemoteUrl has "=eval"
| where RemoteIPType == "Public"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), HostsHit = dcount(DeviceName), Hits = count() by RemoteUrl, tostring(split(RemoteUrl,"/")[2])
| where HostsHit >= 1
| order by FirstSeen desc
```

### Script interpreter spawning PE loader after browser-delivered JS (SocGholish second stage)

`UC_0_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") AND Processes.process_name IN ("powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","cmd.exe","bitsadmin.exe","certutil.exe","curl.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where InitiatingProcessCommandLine has ".js"
| where FileName in~ ("powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","cmd.exe","bitsadmin.exe","certutil.exe","curl.exe","wmic.exe")
   or (FolderPath has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Public\") and FileName endswith ".exe")
| project Timestamp, DeviceName, AccountName,
          GrandparentImage = InitiatingProcessParentFileName,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Shadow copy deletion within 24h of SocGholish script execution (Evil Corp ransomware prelude)

`UC_0_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as scriptTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") AND Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe") AND Processes.process LIKE "%.js%" by Processes.dest Processes.user | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats `summariesonly` count min(_time) as vssTime from datamodel=Endpoint.Processes where (Processes.process_name="vssadmin.exe" AND Processes.process LIKE "%delete shadows%") OR (Processes.process_name="wmic.exe" AND Processes.process LIKE "%shadowcopy%" AND Processes.process LIKE "%delete%") OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process LIKE "%Win32_Shadowcopy%" AND Processes.process LIKE "%Remove%")) by Processes.dest Processes.process | `drop_dm_object_name(Processes)` | rename process as vss_cmd] | eval delta=vssTime-scriptTime | where delta>=0 AND delta<=86400 | table scriptTime vssTime delta dest user vss_cmd
```

**Defender KQL:**
```kql
let LookbackHours = 24h;
let Scripts = DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where AccountName !endswith "$"
  | where FileName in~ ("wscript.exe","cscript.exe")
  | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe")
  | where ProcessCommandLine has ".js"
  | project ScriptTime = Timestamp, DeviceId, DeviceName, AccountName, ScriptCmd = ProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Win32_Shadowcopy","Remove-WmiObject Win32_Shadowcopy","Get-WmiObject Win32_Shadowcopy"))
   or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
| join kind=inner Scripts on DeviceId
| where Timestamp between (ScriptTime .. ScriptTime + LookbackHours)
| project ScriptTime, VssTime = Timestamp,
          DelayMin = datetime_diff('minute', Timestamp, ScriptTime),
          DeviceName, AccountName, ScriptCmd,
          VssBinary = FileName, VssCmd = ProcessCommandLine,
          InitiatingProcessFileName
| order by VssTime desc
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

Severity classified as **HIGH** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
