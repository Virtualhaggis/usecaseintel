# [HIGH] Nearly 300 GitHub repos pose as legit software to push malware

**Source:** BleepingComputer
**Published:** 2026-07-14
**Article:** https://www.bleepingcomputer.com/news/security/nearly-300-github-repos-pose-as-legit-software-to-push-malware/

## Threat Profile

Nearly 300 GitHub repos pose as legit software to push malware 
By Bill Toulas 
July 14, 2026
03:15 PM
0 
A threat actor has published hundreds of fake GitHub repositories impersonating legitimate software and security projects to distribute infostealer malware.
The campaign drew traffic from search results for security products, cryptocurrency services, financial tools, developer utilities, secure email providers, macOS utilities, and gaming software.
The malware collects data from more than 19…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `193.143.1.131`
- **Domain (defanged):** `targetroyena.com`
- **SHA256:** `6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8`
- **SHA256:** `fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56`
- **SHA256:** `8e1ea6d9a8ccb303be9a2aad3524a529d0d99b1b24a136d8422276e942c4c4b8`
- **SHA256:** `e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2`
- **SHA256:** `07dcc12197490bf3292619273ba8b11a960273a34265bca3b7d6d40e8c47dc82`
- **SHA256:** `1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778`
- **SHA256:** `52825dbf3fc28b9f7c3a24adf78d3425ac714e975769f4d70e8c718ddcbb9856`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1608.006** — Stage Capabilities: SEO Poisoning
- **T1189** — Drive-by Compromise
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1620** — Reflective Code Loading
- **T1055.002** — Process Injection: Portable Executable Injection
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1560.001** — Archive Collected Data: Archive via Utility

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake GitHub 'secure download' ZIP fetched from github.io redirector / targetroyena.com

`UC_27_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="193.143.1.131" OR All_Traffic.dest_host="targetroyena.com" OR All_Traffic.dest_host="bentleyvazquezpvey.github.io" OR All_Traffic.url="*targetroyena.com*" OR All_Traffic.url="*bentleyvazquezpvey.github.io*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.url All_Traffic.app All_Traffic.bytes_out | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "193.143.1.131" or RemoteUrl has_any ("targetroyena.com", "bentleyvazquezpvey.github.io")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### WinGUP updater (gup.exe / renamed) side-loads libcurl.dll from user-writable ZIP-extraction path

`UC_27_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="gup.exe" (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\Desktop\\*" OR Processes.process_path="*\\Public\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "libcurl.dll"
| where FolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\", @"\Desktop\", @"\Public\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, LoadedDll = FileName, DllFolderPath = FolderPath, DllSHA256 = SHA256
| order by Timestamp desc
```

### Known BoryptGrab / fake-GitHub sample hashes on process, file, or image-load

`UC_27_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8","fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56","8e1ea6d9a8ccb303be9a2aad3524a529d0d99b1b24a136d8422276e942c4c4b8","1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778","07dcc12197490bf3292619273ba8b11a960273a34265bca3b7d6d40e8c47dc82","e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2","52825dbf3fc28b9f7c3a24adf78d3425ac714e975769f4d70e8c718ddcbb9856") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let iocs = dynamic(["6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8","fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56","8e1ea6d9a8ccb303be9a2aad3524a529d0d99b1b24a136d8422276e942c4c4b8","1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778","07dcc12197490bf3292619273ba8b11a960273a34265bca3b7d6d40e8c47dc82","e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2","52825dbf3fc28b9f7c3a24adf78d3425ac714e975769f4d70e8c718ddcbb9856"]);
union
( DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (iocs) | project Timestamp, DeviceName, Source = "Process", FileName, FolderPath, SHA256, InitiatingProcessFileName ),
( DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in (iocs) | project Timestamp, DeviceName, Source = "ImageLoad", FileName, FolderPath, SHA256, InitiatingProcessFileName ),
( DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (iocs) | project Timestamp, DeviceName, Source = "File", FileName, FolderPath, SHA256, InitiatingProcessFileName = InitiatingProcessFileName )
| order by Timestamp desc
```

### Remote code injection into chrome.exe to defeat App-Bound Encryption (BoryptGrab)

`UC_27_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="chrome.exe" by Processes.dest Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | search parent_process_name!="chrome.exe" parent_process_name!="explorer.exe" parent_process_name!="msedge.exe" parent_process_name!="userinit.exe" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("CreateRemoteThreadApiCall", "QueueUserApcRemoteApiCall", "SetThreadContextRemoteApiCall")
| where FileName =~ "chrome.exe"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "explorer.exe", "services.exe", "svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, Injector = InitiatingProcessFileName, InjectorPath = InitiatingProcessFolderPath, InjectorSHA256 = InitiatingProcessSHA256, TargetProcess = FileName, ActionType
| order by Timestamp desc
```

### BoryptGrab C2 exfil to 193.143.1.131 / targetroyena.com from non-browser process

`UC_27_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count sum(All_Traffic.bytes_out) as bytes_out min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="193.143.1.131" OR All_Traffic.dest_host="targetroyena.com") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | search process_name!="chrome.exe" process_name!="msedge.exe" process_name!="firefox.exe" process_name!="brave.exe" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "193.143.1.131" or RemoteUrl has "targetroyena.com"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, RemoteIP, RemoteUrl, RemotePort
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

### Article-specific behavioural hunt — Nearly 300 GitHub repos pose as legit software to push malware

`UC_27_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Nearly 300 GitHub repos pose as legit software to push malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("libcurl.dll","gup.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("libcurl.dll","gup.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Nearly 300 GitHub repos pose as legit software to push malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("libcurl.dll", "gup.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("libcurl.dll", "gup.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `193.143.1.131`, `targetroyena.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6db05c4473760c44fa572ffac4c5911b35caf2467a37726c21c5f87e25cb2ea8`, `fd01262bd56510088b9ddfe58ca101abb98575f3c0259b480a31b917aa73bc56`, `8e1ea6d9a8ccb303be9a2aad3524a529d0d99b1b24a136d8422276e942c4c4b8`, `e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2`, `07dcc12197490bf3292619273ba8b11a960273a34265bca3b7d6d40e8c47dc82`, `1c854a6aa415f4be964e8a4be49c06e092156bf66d71f9c79995b3e6b156e778`, `52825dbf3fc28b9f7c3a24adf78d3425ac714e975769f4d70e8c718ddcbb9856`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
