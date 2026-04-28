# [CRIT] fast16 | Mystery ShadowBrokers Reference Reveals High-Precision Software Sabotage 5 Years Before Stuxnet

**Source:** SentinelLabs
**Published:** 2026-04-23
**Article:** https://www.sentinelone.com/labs/fast16-mystery-shadowbrokers-reference-reveals-high-precision-software-sabotage-5-years-before-stuxnet/

## Threat Profile

Advanced Persistent Threat 
fast16 | Mystery ShadowBrokers Reference Reveals High-Precision Software Sabotage 5 Years Before Stuxnet 
Vitaly Kamluk & Juan Andrés Guerrero-Saade 
/
April 23, 2026 
Executive Summary 
SentinelLABS has uncovered a previously undocumented cyber sabotage framework whose core components date back to 2005, tracked as fast16.
fast16.sys selectively targets high-precision calculation software, patching code in memory to tamper with results. By combining this payload with …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525`
- **SHA256:** `07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529`
- **SHA256:** `8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9`
- **SHA256:** `5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010`
- **SHA256:** `09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22`
- **SHA256:** `8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0`
- **SHA256:** `06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47`
- **SHA256:** `bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613`
- **SHA256:** `da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1`
- **SHA256:** `aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33`
- **SHA256:** `37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062`
- **SHA256:** `66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2`
- **SHA256:** `c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa`
- **SHA256:** `7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909`
- **SHA256:** `e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a`
- **SHA1:** `de584703c78a60a56028f9834086facd1401b355`
- **SHA1:** `2fa28ef1c6744bdc2021abd4048eefc777dccf22`
- **SHA1:** `586edef41c3b3fba87bf0f0346c7e402f86fc11e`
- **SHA1:** `3ce5b358c2ddd116ac9582efbb38354809999cb5`
- **SHA1:** `650fc6b3e4f62ecdc1ec5728f36bb46ba0f74d05`
- **SHA1:** `d475ace24b9aedebf431efc68f9db32d5ae761bd`
- **SHA1:** `1ce1111702b765f5c4d09315ff1f0d914f7e5c70`
- **SHA1:** `ca665b59bc590292f94c23e04fa458f90d7b20c9`
- **SHA1:** `829f8be65dfe159d2b0dc7ee7a61a017acb54b7b`
- **SHA1:** `e6018cd482c012de8b69c64dc3165337bc121b86`
- **SHA1:** `145ef372c3e9c352eaaa53bb0893749163e49892`
- **SHA1:** `952ed694b60c34ba12df9d392269eae3a4f11be4`
- **SHA1:** `9e089a733fb2740c0e408b2a25d8f5a451584cf6`
- **SHA1:** `92e9dcaf7249110047ef121b7586c81d4b8cb4e5`
- **SHA1:** `675cb83cec5f25ebbe8d9f90dea3d836fcb1c234`
- **MD5:** `dbe51eabebf9d4ef9581ef99844a2944`
- **MD5:** `0ff6abe0252d4f37a196a1231fae5f26`
- **MD5:** `410eddfc19de44249897986ecc8ac449`
- **MD5:** `1d2f32c57ae2f2013f513d342925e972`
- **MD5:** `af4461a149bfd2ba566f2abefe7dcde4`
- **MD5:** `49a8934ccd34e2aaae6ea1e6a6313ffe`
- **MD5:** `e0c10106626711f287ff91c0d6314407`
- **MD5:** `2717b58246237b35d44ef2e49712d3a2`
- **MD5:** `daea40562458fc7ae1adb812137d3d05`
- **MD5:** `2740a703859cbd8b43425d4a2cacb5ec`
- **MD5:** `ebff5b7d4c5becb8715009df596c5a91`
- **MD5:** `cb66a4d52a30bfcd980fe50e7e3f73f0`
- **MD5:** `075b4aa105e728f2b659723e3f36c72c`
- **MD5:** `cf859f164870d113608a843e4a9600ab`
- **MD5:** `f4dbbb78979c1ee8a1523c77065e18a5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
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

### Network connections to article IPs / domains

`UC_NETWORK_IOC` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest IN ("0.0.0.0")
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| append
    [| tstats `summariesonly` count from datamodel=Web
        where Web.dest IN ("example.invalid")
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN ("example.invalid")
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("0.0.0.0") or RemoteUrl has_any ("example.invalid")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Asset exposure — vulnerability matches article CVE(s)

`_uc` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN ("-")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("-")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### File hash IOCs — endpoint file/process match

`UC_HASH_IOC` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN ("9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525", "07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529", "8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9", "5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010", "09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22", "8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0", "06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47", "bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613", "da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1", "aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33", "37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062", "66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2", "c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa", "7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909", "e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a", "de584703c78a60a56028f9834086facd1401b355", "2fa28ef1c6744bdc2021abd4048eefc777dccf22", "586edef41c3b3fba87bf0f0346c7e402f86fc11e", "3ce5b358c2ddd116ac9582efbb38354809999cb5", "650fc6b3e4f62ecdc1ec5728f36bb46ba0f74d05", "d475ace24b9aedebf431efc68f9db32d5ae761bd", "1ce1111702b765f5c4d09315ff1f0d914f7e5c70", "ca665b59bc590292f94c23e04fa458f90d7b20c9", "829f8be65dfe159d2b0dc7ee7a61a017acb54b7b", "e6018cd482c012de8b69c64dc3165337bc121b86", "145ef372c3e9c352eaaa53bb0893749163e49892", "952ed694b60c34ba12df9d392269eae3a4f11be4", "9e089a733fb2740c0e408b2a25d8f5a451584cf6", "92e9dcaf7249110047ef121b7586c81d4b8cb4e5", "675cb83cec5f25ebbe8d9f90dea3d836fcb1c234", "dbe51eabebf9d4ef9581ef99844a2944", "0ff6abe0252d4f37a196a1231fae5f26", "410eddfc19de44249897986ecc8ac449", "1d2f32c57ae2f2013f513d342925e972", "af4461a149bfd2ba566f2abefe7dcde4", "49a8934ccd34e2aaae6ea1e6a6313ffe", "e0c10106626711f287ff91c0d6314407", "2717b58246237b35d44ef2e49712d3a2", "daea40562458fc7ae1adb812137d3d05", "2740a703859cbd8b43425d4a2cacb5ec", "ebff5b7d4c5becb8715009df596c5a91", "cb66a4d52a30bfcd980fe50e7e3f73f0", "075b4aa105e728f2b659723e3f36c72c", "cf859f164870d113608a843e4a9600ab", "f4dbbb78979c1ee8a1523c77065e18a5")
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN ("9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525", "07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529", "8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9", "5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010", "09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22", "8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0", "06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47", "bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613", "da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1", "aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33", "37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062", "66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2", "c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa", "7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909", "e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a", "de584703c78a60a56028f9834086facd1401b355", "2fa28ef1c6744bdc2021abd4048eefc777dccf22", "586edef41c3b3fba87bf0f0346c7e402f86fc11e", "3ce5b358c2ddd116ac9582efbb38354809999cb5", "650fc6b3e4f62ecdc1ec5728f36bb46ba0f74d05", "d475ace24b9aedebf431efc68f9db32d5ae761bd", "1ce1111702b765f5c4d09315ff1f0d914f7e5c70", "ca665b59bc590292f94c23e04fa458f90d7b20c9", "829f8be65dfe159d2b0dc7ee7a61a017acb54b7b", "e6018cd482c012de8b69c64dc3165337bc121b86", "145ef372c3e9c352eaaa53bb0893749163e49892", "952ed694b60c34ba12df9d392269eae3a4f11be4", "9e089a733fb2740c0e408b2a25d8f5a451584cf6", "92e9dcaf7249110047ef121b7586c81d4b8cb4e5", "675cb83cec5f25ebbe8d9f90dea3d836fcb1c234", "dbe51eabebf9d4ef9581ef99844a2944", "0ff6abe0252d4f37a196a1231fae5f26", "410eddfc19de44249897986ecc8ac449", "1d2f32c57ae2f2013f513d342925e972", "af4461a149bfd2ba566f2abefe7dcde4", "49a8934ccd34e2aaae6ea1e6a6313ffe", "e0c10106626711f287ff91c0d6314407", "2717b58246237b35d44ef2e49712d3a2", "daea40562458fc7ae1adb812137d3d05", "2740a703859cbd8b43425d4a2cacb5ec", "ebff5b7d4c5becb8715009df596c5a91", "cb66a4d52a30bfcd980fe50e7e3f73f0", "075b4aa105e728f2b659723e3f36c72c", "cf859f164870d113608a843e4a9600ab", "f4dbbb78979c1ee8a1523c77065e18a5")
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash
     | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ ("9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525", "07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529", "8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9", "5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010", "09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22", "8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0", "06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47", "bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613", "da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1", "aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33", "37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062", "66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2", "c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa", "7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909", "e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a", "de584703c78a60a56028f9834086facd1401b355", "2fa28ef1c6744bdc2021abd4048eefc777dccf22", "586edef41c3b3fba87bf0f0346c7e402f86fc11e", "3ce5b358c2ddd116ac9582efbb38354809999cb5", "650fc6b3e4f62ecdc1ec5728f36bb46ba0f74d05", "d475ace24b9aedebf431efc68f9db32d5ae761bd", "1ce1111702b765f5c4d09315ff1f0d914f7e5c70", "ca665b59bc590292f94c23e04fa458f90d7b20c9", "829f8be65dfe159d2b0dc7ee7a61a017acb54b7b", "e6018cd482c012de8b69c64dc3165337bc121b86", "145ef372c3e9c352eaaa53bb0893749163e49892", "952ed694b60c34ba12df9d392269eae3a4f11be4", "9e089a733fb2740c0e408b2a25d8f5a451584cf6", "92e9dcaf7249110047ef121b7586c81d4b8cb4e5", "675cb83cec5f25ebbe8d9f90dea3d836fcb1c234", "dbe51eabebf9d4ef9581ef99844a2944", "0ff6abe0252d4f37a196a1231fae5f26", "410eddfc19de44249897986ecc8ac449", "1d2f32c57ae2f2013f513d342925e972", "af4461a149bfd2ba566f2abefe7dcde4", "49a8934ccd34e2aaae6ea1e6a6313ffe", "e0c10106626711f287ff91c0d6314407", "2717b58246237b35d44ef2e49712d3a2", "daea40562458fc7ae1adb812137d3d05", "2740a703859cbd8b43425d4a2cacb5ec", "ebff5b7d4c5becb8715009df596c5a91", "cb66a4d52a30bfcd980fe50e7e3f73f0", "075b4aa105e728f2b659723e3f36c72c", "cf859f164870d113608a843e4a9600ab", "f4dbbb78979c1ee8a1523c77065e18a5") or SHA1 in~ ("9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525", "07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529", "8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9", "5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010", "09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22", "8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0", "06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47", "bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613", "da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1", "aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33", "37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062", "66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2", "c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa", "7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909", "e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a", "de584703c78a60a56028f9834086facd1401b355", "2fa28ef1c6744bdc2021abd4048eefc777dccf22", "586edef41c3b3fba87bf0f0346c7e402f86fc11e", "3ce5b358c2ddd116ac9582efbb38354809999cb5", "650fc6b3e4f62ecdc1ec5728f36bb46ba0f74d05", "d475ace24b9aedebf431efc68f9db32d5ae761bd", "1ce1111702b765f5c4d09315ff1f0d914f7e5c70", "ca665b59bc590292f94c23e04fa458f90d7b20c9", "829f8be65dfe159d2b0dc7ee7a61a017acb54b7b", "e6018cd482c012de8b69c64dc3165337bc121b86", "145ef372c3e9c352eaaa53bb0893749163e49892", "952ed694b60c34ba12df9d392269eae3a4f11be4", "9e089a733fb2740c0e408b2a25d8f5a451584cf6", "92e9dcaf7249110047ef121b7586c81d4b8cb4e5", "675cb83cec5f25ebbe8d9f90dea3d836fcb1c234", "dbe51eabebf9d4ef9581ef99844a2944", "0ff6abe0252d4f37a196a1231fae5f26", "410eddfc19de44249897986ecc8ac449", "1d2f32c57ae2f2013f513d342925e972", "af4461a149bfd2ba566f2abefe7dcde4", "49a8934ccd34e2aaae6ea1e6a6313ffe", "e0c10106626711f287ff91c0d6314407", "2717b58246237b35d44ef2e49712d3a2", "daea40562458fc7ae1adb812137d3d05", "2740a703859cbd8b43425d4a2cacb5ec", "ebff5b7d4c5becb8715009df596c5a91", "cb66a4d52a30bfcd980fe50e7e3f73f0", "075b4aa105e728f2b659723e3f36c72c", "cf859f164870d113608a843e4a9600ab", "f4dbbb78979c1ee8a1523c77065e18a5") or MD5 in~ ("9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525", "07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529", "8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9", "5966513a12a5601b262c4ee4d3e32091feb05b666951d06431c30a8cece83010", "09ca719e06a526f70aadf34fb66b136ed20f923776e6b33a33a9059ef674da22", "8b018452fdd64c346af4d97da420681e2e0b55b8c9ce2b8de75e330993b759a0", "06361562cc53d759fb5a4c2b7aac348e4d23fe59be3b2871b14678365283ca47", "bd04715c5c43c862c38a4ad6c2167ad082a352881e04a35117af9bbfad8e5613", "da2b170994031477091be89c8835ff9db1a5304f3f2f25344654f44d0430ced1", "aeaa389453f04a9e79ff6c8b7b66db7b65d4aaffc6cac0bd7957257a30468e33", "37414d9ca87a132ec5081f3e7590d04498237746f9a7479c6b443accee17a062", "66fe485f29a6405265756aaf7f822b9ceb56e108afabd414ee222ee9657dd7e2", "c11a210cb98095422d0d33cbd4e9ecc86b95024f956ede812e17c97e79591cfa", "7e00030a35504de5c0d16020aa40cbaf5d36561e0716feb8f73235579a7b0909", "e775049d1ecf68dee870f1a5c36b2f3542d1182782eb497b8ccfd2309c400b3a", "de584703c78a60a56028f9834086facd1401b355", "2fa28ef1c6744bdc2021abd4048eefc777dccf22", "586edef41c3b3fba87bf0f0346c7e402f86fc11e", "3ce5b358c2ddd116ac9582efbb38354809999cb5", "650fc6b3e4f62ecdc1ec5728f36bb46ba0f74d05", "d475ace24b9aedebf431efc68f9db32d5ae761bd", "1ce1111702b765f5c4d09315ff1f0d914f7e5c70", "ca665b59bc590292f94c23e04fa458f90d7b20c9", "829f8be65dfe159d2b0dc7ee7a61a017acb54b7b", "e6018cd482c012de8b69c64dc3165337bc121b86", "145ef372c3e9c352eaaa53bb0893749163e49892", "952ed694b60c34ba12df9d392269eae3a4f11be4", "9e089a733fb2740c0e408b2a25d8f5a451584cf6", "92e9dcaf7249110047ef121b7586c81d4b8cb4e5", "675cb83cec5f25ebbe8d9f90dea3d836fcb1c234", "dbe51eabebf9d4ef9581ef99844a2944", "0ff6abe0252d4f37a196a1231fae5f26", "410eddfc19de44249897986ecc8ac449", "1d2f32c57ae2f2013f513d342925e972", "af4461a149bfd2ba566f2abefe7dcde4", "49a8934ccd34e2aaae6ea1e6a6313ffe", "e0c10106626711f287ff91c0d6314407", "2717b58246237b35d44ef2e49712d3a2", "daea40562458fc7ae1adb812137d3d05", "2740a703859cbd8b43425d4a2cacb5ec", "ebff5b7d4c5becb8715009df596c5a91", "cb66a4d52a30bfcd980fe50e7e3f73f0", "075b4aa105e728f2b659723e3f36c72c", "cf859f164870d113608a843e4a9600ab", "f4dbbb78979c1ee8a1523c77065e18a5")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
