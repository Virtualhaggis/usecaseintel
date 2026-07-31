# [HIGH] New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA records for configuration recovery

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-21
**Article:** https://securelist.com/project-cav3rn-cyberespionage-framework-using-outlook-and-dns/120757/

## Threat Profile

Table of Contents
Introduction 
Technical details 
C2 communication module 
Outlook calendar events as a C2 channel 
Receiving a command 
Inbound command decryption 
Sending command output 
Heartbeat handling 
DNS AAAA configuration recovery mechanism 
Determining the field length through .p. queries 
Retrieving configuration data through .q. queries 
Failure handling and the sentinel AAAA response 
Infrastructure 
Attribution 
Conclusions 
Indicators of compromise 
File hashes 
Domains and IPs …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `216.126.237.197`
- **IPv4 (defanged):** `144.172.108.205`
- **Domain (defanged):** `cloudlanecdn.com`
- **Domain (defanged):** `ns4.cloudlanecdn.com`
- **Domain (defanged):** `d.53466d4c67515a.0.p.cloudlanecdn.com`
- **Domain (defanged):** `ns1.cloudlanecdn.com`
- **Domain (defanged):** `ns2.cloudlanecdn.com`
- **Domain (defanged):** `ns3.cloudlanecdn.com`
- **Domain (defanged):** `google.com.ayalon-print.co.il`
- **Domain (defanged):** `clipeditskill.com`
- **Domain (defanged):** `accesslinkssl.com`
- **Domain (defanged):** `co.il`
- **Domain (defanged):** `login.microsoftonline.com`
- **Domain (defanged):** `dns1.registrar-servers.com`
- **Domain (defanged):** `dns2.registrar-servers.com`
- **MD5:** `CAF021DDA726B8BA049C2AA395E505A1`
- **MD5:** `C092B02FBC0FDF7EE9608DD016673806`
- **MD5:** `29B2B8C5D99F05BFCDD0D8D976EB5678`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.004** — Application Layer Protocol: DNS
- **T1132.001** — Data Encoding: Standard Encoding
- **T1008** — Fallback Channels
- **T1074.001** — Local Data Staging
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1574.001** — Hijack Execution Flow: DLL
- **T1027.007** — Obfuscated Files: Dynamic API Resolution
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CAV3RN/HOLLOWGRAPH DNS AAAA config-recovery beaconing to cloudlanecdn[.]com

`UC_147_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*.cloudlanecdn.com" OR DNS.query="cloudlanecdn.com") DNS.record_type=AAAA by DNS.src DNS.query DNS.record_type DNS.answer | `drop_dm_object_name(DNS)` | eval config_recovery=if(match(query,"\.(p|q)\.cloudlanecdn\.com$"),"yes","no") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "cloudlanecdn.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
// Defender does not expose DNS query-type; any resolution/connection to cloudlanecdn.com is the C2 domain
```

### CAV3RN AzureCommunication.dll config file 'logAzure.txt' written to disk

`UC_147_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="logAzure.txt" Filesystem.action=created by Filesystem.dest Filesystem.file_path Filesystem.process_id Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName =~ "logAzure.txt"
| project Timestamp, DeviceName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### CAV3RN framework module DLLs loaded/dropped (AzureCommunication / n-HTCommp / masqueraded uxtheme)

`UC_147_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="AzureCommunication.dll" OR Filesystem.file_name="n-HTCommp.dll") OR (Filesystem.file_name="uxtheme.dll" AND NOT (Filesystem.file_path="*\\System32\\*" OR Filesystem.file_path="*\\SysWOW64\\*" OR Filesystem.file_path="*\\WinSxS\\*")) by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("AzureCommunication.dll","n-HTCommp.dll"))
    or (FileName =~ "uxtheme.dll" and FolderPath !has "\\System32\\" and FolderPath !has "\\SysWOW64\\" and FolderPath !has "\\WinSxS\\")
    or (MD5 in~ ("caf021dda726b8ba049c2aa395e505a1","c092b02fbc0fdf7ee9608dd016673806","29b2b8c5d99f05bfcdd0d8d976eb5678"))
| project Timestamp, DeviceName, FileName, FolderPath, MD5, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Anomalous DLL-host process reaching Microsoft Graph/login.microsoftonline for calendar C2

`UC_147_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="graph.microsoft.com" OR All_Traffic.dest="login.microsoftonline.com") (All_Traffic.process_name="rundll32.exe" OR All_Traffic.process_name="regsvr32.exe" OR All_Traffic.process_name="dllhost.exe") by All_Traffic.src All_Traffic.process_name All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("graph.microsoft.com","login.microsoftonline.com")
| where InitiatingProcessFileName in~ ("rundll32.exe","regsvr32.exe","dllhost.exe")
    or InitiatingProcessFolderPath has_any ("\\AppData\\","\\Temp\\","\\ProgramData\\","\\Public\\")
| summarize FirstSeen=min(Timestamp), Endpoints=make_set(RemoteUrl), Count=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| where array_length(Endpoints) >= 1
| order by FirstSeen desc
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Article-specific behavioural hunt — New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA rec

`UC_147_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA rec ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("uxtheme.dll","n-htcommp.dll","azurecommunication.dll","newproject.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("uxtheme.dll","n-htcommp.dll","azurecommunication.dll","newproject.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Project CAV3RN module abuses Outlook calendar events for C2 and DNS AAAA rec
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("uxtheme.dll", "n-htcommp.dll", "azurecommunication.dll", "newproject.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("uxtheme.dll", "n-htcommp.dll", "azurecommunication.dll", "newproject.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `216.126.237.197`, `144.172.108.205`, `cloudlanecdn.com`, `ns4.cloudlanecdn.com`, `d.53466d4c67515a.0.p.cloudlanecdn.com`, `ns1.cloudlanecdn.com`, `ns2.cloudlanecdn.com`, `ns3.cloudlanecdn.com` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `CAF021DDA726B8BA049C2AA395E505A1`, `C092B02FBC0FDF7EE9608DD016673806`, `29B2B8C5D99F05BFCDD0D8D976EB5678`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
