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
This joint action (supported by Europol and Eurojust) was part of Operation Endgame , a major law enforcement operation now aimed at disrupting a key infection chain linked t…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `190.211.254.31`
- **IPv4 (defanged):** `141.193.213.10`
- **IPv4 (defanged):** `45.76.250.221`
- **IPv4 (defanged):** `45.32.199.48`
- **IPv4 (defanged):** `170.75.160.84`
- **IPv4 (defanged):** `31.184.254.115`
- **Domain (defanged):** `editions.seattlemysterylovers.com`
- **Domain (defanged):** `support.traininghub.world`
- **Domain (defanged):** `clients.dedicatedservicesusa.com`
- **Domain (defanged):** `dashnex.plexusmarket.fund`
- **Domain (defanged):** `static.twalls5280.com`
- **Domain (defanged):** `circle.innovativecsportal.com`
- **Domain (defanged):** `change-land.com`
- **Domain (defanged):** `traininghub.world`
- **Domain (defanged):** `dedicatedservicesusa.com`
- **SHA256:** `8f896f3f0b5f33413217e9350dba6d4958cc9bdf568902a08d739b43db6f993b`
- **SHA256:** `2f9e5ea05aa8cd81c1c1f0914220557c5dc4a8bc42ee822bd327e3cfc3328f45`
- **SHA256:** `b151cd35a8aa986bd6bd6f2148fd9ca37e2953e823d658c088923b49e87b4035`
- **SHA256:** `3862b771872c705cb757d851d7714de369cbf8db548d8dcac7edcc46933045e0`
- **SHA256:** `dfc159e0987ac2ea946fd45fa61f81d828a5302d02d53dd7cf88cefefc79c316`
- **SHA256:** `77ba87f9af5738061a9e5b8b8ad3119c2896188928283112dfd0d1882a6a347d`
- **SHA256:** `fce0b35eb3fa3db05e5c6532705758a8669d5bb6fc1825175c0ee67bbbd38862`
- **SHA256:** `a06b40943b4e4d4057756a456e7016b3eae69eeb2c4b1311ce53f5fd9dd7cefa`
- **SHA256:** `d0858a2d532c8bb3bdd8f98ff78c2c16da33c171815aa5c89ffeb84ee76b8cf5`
- **SHA256:** `1140b0fb86f156087d9886e61e8d0c5a3a74ce73648fda609d507e6802b9af5e`
- **SHA256:** `436a97f14051ed97063c9b2e12a25b0068984a0ebe164001e51615539561e64e`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
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

`UC_53_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

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

`UC_53_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

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

`UC_53_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

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

`UC_53_8` · phase: **install** · confidence: **High** · AI-generated for this article

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

`UC_53_9` · phase: **actions** · confidence: **High** · AI-generated for this article

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `190.211.254.31`, `141.193.213.10`, `45.76.250.221`, `45.32.199.48`, `170.75.160.84`, `31.184.254.115`, `editions.seattlemysterylovers.com`, `support.traininghub.world` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8f896f3f0b5f33413217e9350dba6d4958cc9bdf568902a08d739b43db6f993b`, `2f9e5ea05aa8cd81c1c1f0914220557c5dc4a8bc42ee822bd327e3cfc3328f45`, `b151cd35a8aa986bd6bd6f2148fd9ca37e2953e823d658c088923b49e87b4035`, `3862b771872c705cb757d851d7714de369cbf8db548d8dcac7edcc46933045e0`, `dfc159e0987ac2ea946fd45fa61f81d828a5302d02d53dd7cf88cefefc79c316`, `77ba87f9af5738061a9e5b8b8ad3119c2896188928283112dfd0d1882a6a347d`, `fce0b35eb3fa3db05e5c6532705758a8669d5bb6fc1825175c0ee67bbbd38862`, `a06b40943b4e4d4057756a456e7016b3eae69eeb2c4b1311ce53f5fd9dd7cefa` _(+3 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
