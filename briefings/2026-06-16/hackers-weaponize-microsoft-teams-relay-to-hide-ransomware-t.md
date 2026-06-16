# [HIGH] Hackers Weaponize Microsoft Teams Relay to Hide Ransomware Traffic

**Source:** Cyber Security News
**Published:** 2026-06-16
**Article:** https://cybersecuritynews.com/microsoft-teams-relay-abused/

## Threat Profile

Hackers are increasingly abusing trusted cloud services to evade detection, and a newly uncovered campaign demonstrates how Microsoft Teams infrastructure can be weaponized to hide malicious traffic. According to&#160;the Symantec Threat Hunter Team, a new Go-based remote access Trojan (RAT) named Backdoor.TURN leverages Microsoft Teams TURN relay servers to disguise command-and-control (C2) communications as legitimate [&#8230;] The post Hackers Weaponize Microsoft Teams Relay to Hide Ransomwar…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-52271`
- **CVE:** `CVE-2025-61155`
- **CVE:** `CVE-2025-1055`
- **IPv4 (defanged):** `62.164.177.25`
- **IPv4 (defanged):** `192.36.27.51`
- **Domain (defanged):** `projetosmecanicos.com.br`
- **Domain (defanged):** `socialbizsolutions.com`
- **Domain (defanged):** `professionalhomebasedbusiness.com`
- **Domain (defanged):** `safefire.jo`
- **Domain (defanged):** `glanz-gmbh.de`
- **Domain (defanged):** `turnkeyaiagents.com`
- **Domain (defanged):** `comunidadesparentais.com.br`
- **Domain (defanged):** `mysimerp.net`
- **SHA256:** `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b`
- **SHA256:** `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6`
- **SHA256:** `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383`
- **SHA256:** `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0`
- **SHA256:** `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b`
- **SHA256:** `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219`
- **SHA256:** `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3`
- **SHA256:** `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759`
- **SHA256:** `cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a`
- **SHA256:** `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877`
- **SHA256:** `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e`
- **SHA256:** `8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2`
- **SHA256:** `65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951`
- **SHA256:** `6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4`
- **SHA256:** `252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab`
- **SHA256:** `8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531`
- **SHA256:** `e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22`
- **SHA256:** `087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2`
- **SHA256:** `048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c`
- **SHA256:** `6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e`
- **SHA256:** `d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e`
- **SHA256:** `aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
  - IP / domain IOC(s): `62.164.177.25`, `192.36.27.51`, `projetosmecanicos.com.br`, `socialbizsolutions.com`, `professionalhomebasedbusiness.com`, `safefire.jo`, `glanz-gmbh.de`, `turnkeyaiagents.com` _(+2 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-52271`, `CVE-2025-61155`, `CVE-2025-1055`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b`, `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6`, `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383`, `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0`, `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b`, `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219`, `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3`, `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759` _(+14 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
