# [CRIT] Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and India

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-30
**Article:** https://securelist.com/silver-fox-tax-notification-campaign/119575/

## Threat Profile

Table of Contents
Email campaign 
RustSL loader 
Silver Fox RustSL 
The steganography.rs module 
Encrypted malicious payload format 
The guard.rs module 
Phantom Persistence 
Attack chain and payloads 
Custom ValleyRAT modules 
ABCDoor Python backdoor 
ABCDoor versions 
Evolution of ABCDoor distribution methods 
Victims 
Conclusion 
Detection by Kaspersky solutions 
Indicators of compromise 
Authors
Anton Kargin 
Vladimir Gursky 
Victoria Vlasova 
Anna Lazaricheva 
In December 2025, we detected …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `207.56.138.28`
- **IPv4 (defanged):** `154.82.81.205`
- **IPv4 (defanged):** `45.118.133.203`
- **IPv4 (defanged):** `108.187.37.85`
- **IPv4 (defanged):** `108.187.42.63`
- **IPv4 (defanged):** `108.187.41.221`
- **IPv4 (defanged):** `154.82.81.192`
- **IPv4 (defanged):** `139.180.128.251`
- **IPv4 (defanged):** `192.229.115.229`
- **IPv4 (defanged):** `207.56.119.216`
- **IPv4 (defanged):** `192.163.167.14`
- **IPv4 (defanged):** `45.192.219.60`
- **IPv4 (defanged):** `192.238.205.47`
- **IPv4 (defanged):** `45.32.108.178`
- **IPv4 (defanged):** `57.133.212.106`
- **Domain (defanged):** `abc.haijing88.com`
- **Domain (defanged):** `mcagov.cc`
- **Domain (defanged):** `abc.fetish-friends.com`
- **Domain (defanged):** `tinyurl.com`
- **Domain (defanged):** `roldco.com`
- **Domain (defanged):** `sudsmama.com`
- **Domain (defanged):** `vnc.kcii2.com`
- **Domain (defanged):** `abc.3mkorealtd.com`
- **Domain (defanged):** `abc.sudsmama.com`
- **Domain (defanged):** `abc.woopami.com`
- **Domain (defanged):** `abc.ilptour.com`
- **Domain (defanged):** `abc.petitechanson.com`
- **Domain (defanged):** `abc.doublemobile.com`
- **MD5:** `e6362a81991323e198a463a8ce255533`
- **MD5:** `2c5a1dd4cb53287fe0ed14e0b7b7b1b7`
- **MD5:** `fc546acf1735127db05fb5bc354093e0`
- **MD5:** `4a5195a38a458cdd2c1b5ab13af3b393`
- **MD5:** `e66bae6e8621db2a835fa6721c3e5bbe`
- **MD5:** `2375193669e243e830ef5794226352e7`
- **MD5:** `5b998a5bc5ad1c550564294034d4a62c`
- **MD5:** `c50c980d3f4b7ed970f083b0d37a6a6a`
- **MD5:** `de8f0008b15f2404f721f76fac34456a`
- **MD5:** `9bf9f635019494c4b70fb0a7c0fb53e4`
- **MD5:** `a543b96b0938de798dd4f683dd92a94a`
- **MD5:** `fa08b243f12e31940b8b4b82d3498804`
- **MD5:** `13669b8f2bd0af53a3fe9ac0490499e5`
- **MD5:** `04194f8ddd0518fd8005f0e87ae96335`
- **MD5:** `f15a67899cfe4decff76d4cd1677c254`
- **MD5:** `11705121f64fa36f1e9d7e59867b0724`
- **MD5:** `4d343515f4c87b9a2ffd2f46665d2d57`
- **MD5:** `dfc64dd9d8f776ca5440c35fef5d406e`
- **MD5:** `eefc28e9f2c0c0592af186be8e3570d2`
- **MD5:** `6cf382d3a0eae57b8baaa263e4ed8d00`
- **MD5:** `32407207e9e9a0948d167dca96c41d1a`
- **MD5:** `d17caf6f5d6ba3393a3a865d1c43c3d2`
- **MD5:** `6495c409b59deb72cfcb2b2da983b3bb`
- **MD5:** `b500e0a8c87dffe6f20c6e067b51afbf`
- **MD5:** `814032eec3bc31643f8faa4234d0e049`
- **MD5:** `90257aa1e7c9118055c09d4a978d4bee`
- **MD5:** `f8371097121549feb21e3bcc2eeea522`
- **MD5:** `2b92e125184469a0c3740abcaa10350c`
- **MD5:** `043e457726f1bbb6046cb0c9869dbd7d`
- **MD5:** `1AA72CD19E37570E14D898DFF3F2E380`
- **MD5:** `79CD56FC9ABF294B9BA8751E618EC642`
- **MD5:** `0B9B420E3EDD2ADE5EDC44F60CA745A2`
- **MD5:** `6611E902945E97A1B27F322A50566D48`
- **MD5:** `84E54C3602D8240ED905B07217C451CD`
- **MD5:** `B53E3CC11947E5645DFBB19934B69833`
- **MD5:** `0C3B60FFC4EA9CCCE744BFA03B1A3556`
- **MD5:** `039E93B98EF5E329F8666A424237AE73`
- **MD5:** `B6DF7C59756AB655CA752B8A1B20CFFA`
- **MD5:** `5390E8BF7131CAAAA98A5DD63E27B2BC`
- **MD5:** `44299A368000AE1EE9E9E584377B8757`
- **MD5:** `E5E8EF65B4D265BD5FB77FE165131C2F`
- **MD5:** `3279307508F3E5FB3A2420DEC645F583`
- **MD5:** `1020497BEF56F4181AEFB7A0A9873FB4`
- **MD5:** `B23D302B7F23453C98C11CA7B2E4616E`
- **MD5:** `A234850DFDFD7EE128F648F9750DD2C4`
- **MD5:** `4FC5EC1DE89CE3FCDD3E70DB4A9C39D1`
- **MD5:** `A0D1223CA4327AA5F7674BDA8779323F`
- **MD5:** `70AE9CA2A285DA9005A8ACB32DD31ACE`
- **MD5:** `DD0114FFACC6610B5A4A1CB0E79624CC`
- **MD5:** `891DE2FF486A1824F2DB01C1BDF1D2E9`
- **MD5:** `B0E06925DB5416DFC90BABF46402CD6F`
- **MD5:** `AD39A5790B79178D02AC739099B8E1F4`
- **MD5:** `D1D78CD1436991ADB9C005CC7C6B5B98`
- **MD5:** `CB3D86E3EC2736EE1C883706FCA172F8`
- **MD5:** `A083C546DC66B0F2A5E0E2E68032F62C`
- **MD5:** `70016DDBCB8543BDB06E0F8C509EE980`
- **MD5:** `8FC911CA37F9F451A213B967F016F1F8`
- **MD5:** `202A5BCB87C34993318CFA3FA0C7ECB0`
- **MD5:** `06130DC648621E93ACB9EFB9FABB9651`
- **MD5:** `F7037CC9A5659D5A1F68E88582242375`
- **MD5:** `8AC5BEE89436B29F9817E434507FEF55`
- **MD5:** `5ED84B2099E220D645934E1FD552AE3A`
- **MD5:** `27A3C439308F5C4956D77E23E1AAD1A9`
- **MD5:** `53B68CA8D7A54C15700CF9500AE4A4E2`
- **MD5:** `1D1F71936DB05F67765F442FEB95F3FD`
- **MD5:** `3C6AEC25EBB2D51E1F16C2EEF181C82A`
- **MD5:** `7F27818E4244310A645984CCC41EA818`
- **MD5:** `A75713F0310E74FFD24D91E5731C4D31`
- **MD5:** `4FC8C78516A8C2130286429686E200ED`
- **MD5:** `3417B9CF7ACB22FAE9E24603D4DE1194`
- **MD5:** `933F1CB8ED2CED5D0DD2877C5EA374E8`
- **MD5:** `B5CA812843570DCF8E7F35CACAB36D4A`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1614.001** — System Location Discovery: System Language Discovery
- **T1016** — System Network Configuration Discovery
- **T1480.001** — Execution Guardrails: Environmental Keying
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Silver Fox RustSL Phantom Persistence — RunOnce 'Application Restart #' registered by csrss.exe pointing to user-writable path

`UC_209_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as registry_value_data values(Registry.process_name) as process_name from datamodel=Endpoint.Registry where Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\RunOnce*" Registry.registry_value_name="Application Restart #*" by Registry.dest Registry.registry_key_name Registry.registry_value_name Registry.user | `drop_dm_object_name(Registry)` | where NOT match(registry_value_data, "(?i)^\"?(C:\\\\Program Files|C:\\\\Program Files \\(x86\\)|C:\\\\Windows\\\\System32|C:\\\\Windows\\\\SysWOW64|C:\\\\Windows\\\\Microsoft\\.NET)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Silver Fox / RustSL Phantom Persistence — csrss.exe writes RunOnce 'Application Restart #N' on behalf of the malware
let _trusted_prefixes = dynamic([@"C:\Program Files\", @"C:\Program Files (x86)\", @"C:\Windows\System32\", @"C:\Windows\SysWOW64\", @"C:\Windows\Microsoft.NET\"]);
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\RunOnce"
| where RegistryValueName startswith "Application Restart #"
| where InitiatingProcessFileName =~ "csrss.exe"   // Phantom Persistence triggers csrss to write the RunOnce on behalf of the abuser
| extend ValueLower = tolower(RegistryValueData)
| where not(ValueLower startswith @"""c:\program files")
   and not(ValueLower startswith @"""c:\program files (x86)")
   and not(ValueLower startswith @"c:\program files\")
   and not(ValueLower startswith @"c:\program files (x86)\")
   and not(ValueLower startswith @"c:\windows\system32\")
   and not(ValueLower startswith @"c:\windows\syswow64\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] RustSL guard.rs geofencing — single process queries 3+ public IP-geolocation services in a short window

`UC_209_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Web.url) as urls dc(Web.url) as service_count from datamodel=Web.Web where (Web.url="*ip-api.com*" OR Web.url="*ipwho.is*" OR Web.url="*ipinfo.io*" OR Web.url="*ipapi.co*" OR Web.url="*geoplugin.net*") by Web.dest Web.src Web.process Web.user _time span=5m | `drop_dm_object_name(Web)` | eval distinct_geo_services=mvcount(mvdedup(mvfilter(match(urls, "(ip-api\.com|ipwho\.is|ipinfo\.io|ipapi\.co|geoplugin\.net)")))) | where service_count>=3
```

**Defender KQL:**
```kql
// RustSL guard.rs — same process pings 3+ of the article's IP-geolocation reflectors within 5 minutes
let _services = dynamic(["ip-api.com","ipwho.is","ipinfo.io","ipapi.co","geoplugin.net"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| extend Service = case(
    RemoteUrl has "ip-api.com", "ip-api.com",
    RemoteUrl has "ipwho.is", "ipwho.is",
    RemoteUrl has "ipinfo.io", "ipinfo.io",
    RemoteUrl has "ipapi.co", "ipapi.co",
    RemoteUrl has "geoplugin.net", "geoplugin.net",
    "")
| where Service != ""
| summarize Services = make_set(Service),
            ServiceCount = dcount(Service),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            ConnCount = count()
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, bin(Timestamp, 5m)
| where ServiceCount >= 3                       // 3+ of the 5 reflectors guard.rs uses
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","safari.exe","iexplore.exe","curl.exe")  // browser noise
| order by FirstSeen desc
```

### [LLM] Silver Fox January-2026 campaign IOC sweep — ValleyRAT C2 207.56.138.28:6666 + RustSL distribution domains/hashes

`UC_209_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="207.56.138.28" OR All_Traffic.dest_ip="154.82.81.205" OR All_Traffic.dest_ip="154.82.81.192" OR All_Traffic.dest_ip="45.118.133.203" OR All_Traffic.dest_ip="108.187.37.85" OR All_Traffic.dest_ip="108.187.42.63" OR All_Traffic.dest_ip="108.187.41.221" OR All_Traffic.dest_ip="139.180.128.251") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("e6362a81991323e198a463a8ce255533","2c5a1dd4cb53287fe0ed14e0b7b7b1b7","fc546acf1735127db05fb5bc354093e0","4a5195a38a458cdd2c1b5ab13af3b393","e66bae6e8621db2a835fa6721c3e5bbe","2375193669e243e830ef5794226352e7","5b998a5bc5ad1c550564294034d4a62c","c50c980d3f4b7ed970f083b0d37a6a6a")) by Processes.dest Processes.user Processes.process_name Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)`] | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="abc.haijing88.com" OR DNS.query="mcagov.cc" OR DNS.query="abc.fetish-friends.com" OR DNS.query="vnc.kcii2.com" OR DNS.query="abc.3mkorealtd.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Silver Fox Jan-2026 IOC sweep — C2 IPs, RustSL distribution domains, and loader hashes
let _ips = dynamic(["207.56.138.28","154.82.81.205","154.82.81.192","45.118.133.203","108.187.37.85","108.187.42.63","108.187.41.221","139.180.128.251"]);
let _domains = dynamic(["abc.haijing88.com","mcagov.cc","abc.fetish-friends.com","vnc.kcii2.com","abc.3mkorealtd.com"]);
let _md5s = dynamic(["e6362a81991323e198a463a8ce255533","2c5a1dd4cb53287fe0ed14e0b7b7b1b7","fc546acf1735127db05fb5bc354093e0","4a5195a38a458cdd2c1b5ab13af3b393","e66bae6e8621db2a835fa6721c3e5bbe","2375193669e243e830ef5794226352e7","5b998a5bc5ad1c550564294034d4a62c","c50c980d3f4b7ed970f083b0d37a6a6a"]);
let _net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (_ips) or (isnotempty(RemoteUrl) and _domains has_any (RemoteUrl))
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, IndicatorType="network", Indicator=coalesce(RemoteUrl, RemoteIP), RemotePort, ProcImage=InitiatingProcessFolderPath, ProcCmd=InitiatingProcessCommandLine, SHA256=InitiatingProcessSHA256;
let _proc = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where MD5 in (_md5s) or InitiatingProcessMD5 in (_md5s)
    | project Timestamp, DeviceName, AccountUpn, IndicatorType="process_hash", Indicator=coalesce(MD5, InitiatingProcessMD5), RemotePort=int(null), ProcImage=FolderPath, ProcCmd=ProcessCommandLine, SHA256;
let _file = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where MD5 in (_md5s)
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, IndicatorType="file_hash", Indicator=MD5, RemotePort=int(null), ProcImage=FolderPath, ProcCmd=InitiatingProcessCommandLine, SHA256;
union _net, _proc, _file
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

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and I

`UC_209_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and I ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("file.exe","online-module.dll","login-module.dll","curl.exe","ffmpeg.exe","update.bat","pythonw.exe","__main__.py","main.py","path_to_pythonw.exe","update.ps1","suvidha.exe","gstsuvidha.exe","remoteinstaller_20250803165259_whatsapp.exe","remoteinstaller_20250806_004447_jiqi.exe") OR Processes.process="*-WindowStyle Hidden*" OR Processes.process_path="*C:\Users\Administrator\Desktop\bat\Release\winos4.0*" OR Processes.process_path="*%LOCALAPPDATA%\appclient\111.zip*" OR Processes.process_path="*%LOCALAPPDATA%\appclient\111.zip.*" OR Processes.process_path="*\AppData\Local\appclient\update.bat*" OR Processes.process_path="*C:\ProgramData\Tailscale.*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Administrator\Desktop\bat\Release\winos4.0*" OR Filesystem.file_path="*%LOCALAPPDATA%\appclient\111.zip*" OR Filesystem.file_path="*%LOCALAPPDATA%\appclient\111.zip.*" OR Filesystem.file_path="*\AppData\Local\appclient\update.bat*" OR Filesystem.file_path="*C:\ProgramData\Tailscale.*" OR Filesystem.file_path="*C:\ProgramData\Tailscale*" OR Filesystem.file_path="*\AppData\Local\appclient\python\pythonw.exe*" OR Filesystem.file_path="*%LOCALAPPDATA%\applogs\device.log.*" OR Filesystem.file_name IN ("file.exe","online-module.dll","login-module.dll","curl.exe","ffmpeg.exe","update.bat","pythonw.exe","__main__.py","main.py","path_to_pythonw.exe","update.ps1","suvidha.exe","gstsuvidha.exe","remoteinstaller_20250803165259_whatsapp.exe","remoteinstaller_20250806_004447_jiqi.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Silver Fox uses the new ABCDoor backdoor to target organizations in Russia and I
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("file.exe", "online-module.dll", "login-module.dll", "curl.exe", "ffmpeg.exe", "update.bat", "pythonw.exe", "__main__.py", "main.py", "path_to_pythonw.exe", "update.ps1", "suvidha.exe", "gstsuvidha.exe", "remoteinstaller_20250803165259_whatsapp.exe", "remoteinstaller_20250806_004447_jiqi.exe") or ProcessCommandLine has_any ("-WindowStyle Hidden") or FolderPath has_any ("C:\Users\Administrator\Desktop\bat\Release\winos4.0", "%LOCALAPPDATA%\appclient\111.zip", "%LOCALAPPDATA%\appclient\111.zip.", "\AppData\Local\appclient\update.bat", "C:\ProgramData\Tailscale."))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Administrator\Desktop\bat\Release\winos4.0", "%LOCALAPPDATA%\appclient\111.zip", "%LOCALAPPDATA%\appclient\111.zip.", "\AppData\Local\appclient\update.bat", "C:\ProgramData\Tailscale.", "C:\ProgramData\Tailscale", "\AppData\Local\appclient\python\pythonw.exe", "%LOCALAPPDATA%\applogs\device.log.") or FileName in~ ("file.exe", "online-module.dll", "login-module.dll", "curl.exe", "ffmpeg.exe", "update.bat", "pythonw.exe", "__main__.py", "main.py", "path_to_pythonw.exe", "update.ps1", "suvidha.exe", "gstsuvidha.exe", "remoteinstaller_20250803165259_whatsapp.exe", "remoteinstaller_20250806_004447_jiqi.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `207.56.138.28`, `154.82.81.205`, `45.118.133.203`, `108.187.37.85`, `108.187.42.63`, `108.187.41.221`, `154.82.81.192`, `139.180.128.251` _(+20 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e6362a81991323e198a463a8ce255533`, `2c5a1dd4cb53287fe0ed14e0b7b7b1b7`, `fc546acf1735127db05fb5bc354093e0`, `4a5195a38a458cdd2c1b5ab13af3b393`, `e66bae6e8621db2a835fa6721c3e5bbe`, `2375193669e243e830ef5794226352e7`, `5b998a5bc5ad1c550564294034d4a62c`, `c50c980d3f4b7ed970f083b0d37a6a6a` _(+64 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
