# [CRIT] From PDB strings to MaaS: Tracking a commodity BadIIS ecosystem used by Chinese-speaking threat

**Source:** Cisco Talos
**Published:** 2026-05-19
**Article:** https://blog.talosintelligence.com/from-pdb-strings-to-maas-tracking-a-commodity-badiis-ecosystem/

## Threat Profile

From PDB strings to MaaS: Tracking a commodity BadIIS ecosystem used by Chinese-speaking threat 
By 
Joey Chen 
Tuesday, May 19, 2026 06:00
Threat Spotlight
Cisco Talos has uncovered a BadIIS variant — identifiable by its embedded "demo.pdb" strings — that functions as commodity malware. This variant is likely sold or shared among multiple Chinese-speaking cybercrime groups that operate under a  malware-as-a-service (MaaS)  model for continuous monetization. 
Analysis of program database (PDB) f…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `143.92.36.109`
- **IPv4 (defanged):** `38.181.52.147`
- **IPv4 (defanged):** `154.23.186.99`
- **IPv4 (defanged):** `154.36.149.4`
- **IPv4 (defanged):** `45.194.17.133`
- **Domain (defanged):** `lee.6686ty.vip`
- **Domain (defanged):** `iis.01nmwe.xyz`
- **SHA256:** `79b3c217f5b7c257d8c7f4c8166102e9754208e60306aa3f4bf917e765fac8ea`
- **SHA256:** `d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf`
- **SHA256:** `80e9a39292b7af7b9831563799776808e597bade3fba4f4d7b25b6833a8c7e5a`
- **SHA256:** `ff8095aba365885b0886da894794ac45ae5e0c3363a45ae106383e5bd1353941`
- **SHA256:** `5904b42d8099a6657ea21a6af0ae9bd50ae7ca4b619fee125df133051cff2b8a`
- **SHA256:** `4091ddc3560fb60bd3ef071367fd833d67c3c6e3e81165aa3d93519b93959658`
- **SHA256:** `fa15ba707356cb474c16ce04abd86ae9d074763ab965e3766d6af56f37003dda`
- **SHA256:** `c732067b3d8763c248051366ab7beeae0d7fbe105884d4d3f8647e3427f36daf`
- **SHA256:** `521869f9ee6066c33fb1615cbcad66de157876bd08cec05597e4d3a0405efac8`
- **SHA256:** `524a9dfe12299ec9cc3148692b620130c7e767ed0430f211be4128a82c0fdafc`
- **SHA256:** `bbf9d7dafba979ef9c1e8531a20d3bea1adcdbb628816ce8781d7eeb6292f265`
- **SHA256:** `e7d8b5647917589949634155d936d8aa4dd25307a9292fb43d47281001859a9b`
- **SHA256:** `b9ba4c4fff3f5042805b2d75484fdf4e0a7e067cfa560b07544570e20775457e`
- **SHA256:** `b0f419467a36a9ab71fe0aa8e1587377d668789b18907ec0993cb549c61c9d42`
- **SHA256:** `e1c117bfa71d0cf5e9305839d56c73752be53bd6426d4c2b4f5d51ee3735d8e6`
- **SHA256:** `0ebe923b7bc39489532b377c69ce808c38206dd931286d0b0b4bf7b245020174`
- **SHA256:** `eda7a7edc01392706a872a5a275940b4a4b9471dc562eb70128ee672872d1407`
- **SHA256:** `44bfb9f0e13dd72ed111b5b5600b80b305ab153a0ee2224957e76391b28ac037`
- **SHA256:** `03fef9805e2e7dfd31d9277253fbc1a5c3eddeedee4e1950e42f860b7e936287`
- **SHA256:** `65967f471440449d2f1b615ff1338b8082b0481b617eda4d9f21a9f102b98859`
- **SHA256:** `f9017361349421728fc1ac1bc1549b3d23b35bd795f0a83be2e9e517bccaccdc`
- **SHA256:** `1bb1187daff9610a0c142b48bc04d3e883344ca0eca8fe915d6a02fb3e7571ff`
- **SHA256:** `402c616229aa0c7f98cfc3f4e9781c2468bd79c2d23da1cdf38172cb082a8a9c`
- **SHA256:** `7a0e2aee8141c06558347dc4800daba06ab337c5619ba501da49ed03adf8175e`
- **SHA256:** `59b416efff07208dc8b1c98a6f754e3abc14e55d71971ddc5581f6bc7ca45837`
- **SHA256:** `f1dcd2809a001a0d0ea3221939f7afd2ef9e5bf468709bd91abd70c902c42d45`
- **SHA256:** `01577f5b0869154fb678bcf86eef50afceb5fc189c87b2085fe5fcdf74cd6ff0`
- **SHA256:** `144129f42081dbbacbbd15688dc5f4dcb97c3dd17cc1352abe80b524c0ea7ca8`
- **SHA256:** `fdbe78935bd3f56df43a4702b83a568881f119e43236e92ecf10ca19eac6b87f`
- **SHA256:** `9eb45f6f529f9f385a87b13c41351800a1046718d45e7d99e1feb053c26d469f`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1543.003** — Windows Service
- **T1027** — Obfuscated Files or Information
- **T1543.003** — Persistence (article-specific)
- **T1505.004** — Server Software Component: IIS Components
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1090** — Proxy
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1565.001** — Stored Data Manipulation
- **T1608.006** — Stage Capabilities: SEO Poisoning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] BadIIS demo.pdb variant known SHA256 file/process hashes

`UC_146_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("79b3c217f5b7c257d8c7f4c8166102e9754208e60306aa3f4bf917e765fac8ea","d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf","80e9a39292b7af7b9831563799776808e597bade3fba4f4d7b25b6833a8c7e5a","ff8095aba365885b0886da894794ac45ae5e0c3363a45ae106383e5bd1353941","5904b42d8099a6657ea21a6af0ae9bd50ae7ca4b619fee125df133051cff2b8a","4091ddc3560fb60bd3ef071367fd833d67c3c6e3e81165aa3d93519b93959658","fa15ba707356cb474c16ce04abd86ae9d074763ab965e3766d6af56f37003dda","c732067b3d8763c248051366ab7beeae0d7fbe105884d4d3f8647e3427f36daf") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let HashIOC = dynamic(["79b3c217f5b7c257d8c7f4c8166102e9754208e60306aa3f4bf917e765fac8ea","d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf","80e9a39292b7af7b9831563799776808e597bade3fba4f4d7b25b6833a8c7e5a","ff8095aba365885b0886da894794ac45ae5e0c3363a45ae106383e5bd1353941","5904b42d8099a6657ea21a6af0ae9bd50ae7ca4b619fee125df133051cff2b8a","4091ddc3560fb60bd3ef071367fd833d67c3c6e3e81165aa3d93519b93959658","fa15ba707356cb474c16ce04abd86ae9d074763ab965e3766d6af56f37003dda","c732067b3d8763c248051366ab7beeae0d7fbe105884d4d3f8647e3427f36daf"]);
union
( DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (HashIOC) | project Timestamp, Source="FileEvent", DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName ),
( DeviceImageLoadEvents | where Timestamp > ago(30d) | where SHA256 in (HashIOC) | project Timestamp, Source="ImageLoad", DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=InitiatingProcessAccountName ),
( DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (HashIOC) | project Timestamp, Source="ProcessCreate", DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessAccountName=AccountName )
| order by Timestamp desc
```

### [LLM] BadIIS C2 IP / domain beacon (lee.6686ty.vip, iis.01nmwe.xyz)

`UC_146_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("143.92.36.109","38.181.52.147","154.23.186.99","154.36.149.4","45.194.17.133") OR All_Traffic.dest_host IN ("lee.6686ty.vip","iis.01nmwe.xyz") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let IpIOC = dynamic(["143.92.36.109","38.181.52.147","154.23.186.99","154.36.149.4","45.194.17.133"]);
let DomainIOC = dynamic(["lee.6686ty.vip","iis.01nmwe.xyz"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IpIOC) or RemoteUrl has_any (DomainIOC)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] IIS worker (w3wp.exe) initiating outbound connection to public IP

`UC_146_7` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dests values(All_Traffic.dest_port) as ports dc(All_Traffic.dest) as distinct_dest_count from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name="w3wp.exe" AND NOT (All_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16")) AND All_Traffic.dest_port IN ("80","443","8080","8443") by All_Traffic.src All_Traffic.user All_Traffic.process_name | where distinct_dest_count > 1 | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where RemoteIPType == "Public"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","ConnectionRequest")
| where RemotePort in (80, 443, 8080, 8443)
| summarize ConnCount=count(), DistinctDests=dcount(RemoteIP), SampleUrl=any(RemoteUrl), SampleCmd=any(InitiatingProcessCommandLine), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where ConnCount > 3
| order by ConnCount desc
```

### [LLM] IIS native module DLL drop or applicationHost.config modification by non-IIS process

`UC_146_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\inetsrv\\config\\applicationHost.config" OR Filesystem.file_path="*\\System32\\inetsrv\\*.dll" OR Filesystem.file_path="*\\Microsoft.NET\\Framework64\\*\\*.dll" OR Filesystem.file_path="*\\Microsoft.NET\\Framework\\*\\*.dll") AND NOT Filesystem.process_name IN ("TrustedInstaller.exe","msiexec.exe","mscorsvw.exe","appcmd.exe","iissetup.exe","WindowsAdminCenter.exe","setup.exe","WaAppAgent.exe","WindowsAzureGuestAgent.exe","MsDeploy.exe","ngen.exe") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\inetsrv\" and FileName endswith ".dll")
    or (FolderPath has @"\Microsoft.NET\Framework64\" and FileName endswith ".dll")
    or (FolderPath has @"\Microsoft.NET\Framework\" and FileName endswith ".dll")
    or FileName =~ "applicationHost.config"
| where InitiatingProcessFileName !in~ ("TrustedInstaller.exe","msiexec.exe","mscorsvw.exe","iissetup.exe","appcmd.exe","WindowsAdminCenter.exe","WaAppAgent.exe","WindowsAzureGuestAgent.exe","MsDeploy.exe","ngen.exe","setup.exe","trustedinstaller.exe")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] IIS worker (w3wp.exe) writing robots.txt / .php / .js into web root

`UC_146_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="w3wp.exe" AND (Filesystem.file_name="robots.txt" OR Filesystem.file_path="*\\wwwroot\\*.php" OR Filesystem.file_path="*\\wwwroot\\*.js" OR Filesystem.file_path="*\\wwwroot\\*.html" OR Filesystem.file_path="*\\inetpub\\*\\robots.txt") AND Filesystem.action IN ("created","modified","written") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FileName =~ "robots.txt")
    or (FolderPath has @"\inetpub\wwwroot\" and (FileName endswith ".php" or FileName endswith ".js" or FileName endswith ".html" or FileName endswith ".htm"))
    or (FolderPath has @"\inetpub\" and FileName =~ "robots.txt")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
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

### Service install for persistence — sc.exe / new service registry write

`UC_SERVICE_PERSIST` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\Users\*" OR Processes.process="*\AppData\*"
        OR Processes.process="*\ProgramData\*" OR Processes.process="*\Temp\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\Users\*"
            OR Registry.registry_value_data="*\AppData\*"
            OR Registry.registry_value_data="*\Temp\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\Users\|\AppData\|\ProgramData\|\Temp\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### Article-specific behavioural hunt — From PDB strings to MaaS: Tracking a commodity BadIIS ecosystem used by Chinese-

`UC_146_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — From PDB strings to MaaS: Tracking a commodity BadIIS ecosystem used by Chinese- ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("32.dll","64.dll") OR Processes.process_path="*C:\Users\Administrator\Desktop\2021-09-30\x64\Release\demo.pdb*" OR Processes.process_path="*C:\Users\Administrator\Desktop\iis\x64\Release\demo.pdb*" OR Processes.process_path="*C:\Users\Administrator\Desktop\dll\x64\Release\demo.pdb*" OR Processes.process_path="*C:\Users\Administrator\Desktop\dll0217\Release\demo.pdb*" OR Processes.process_path="*C:\Users\Administrator\Desktop\dll0217\x64\Release\demo.pdb*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Administrator\Desktop\2021-09-30\x64\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\iis\x64\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\dll\x64\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\dll0217\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\dll0217\x64\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\dll0301\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\dll0301\x64\Release\demo.pdb*" OR Filesystem.file_path="*C:\Users\Administrator\Desktop\dll0315\Release\demo.pdb*" OR Filesystem.file_name IN ("32.dll","64.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — From PDB strings to MaaS: Tracking a commodity BadIIS ecosystem used by Chinese-
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("32.dll", "64.dll") or FolderPath has_any ("C:\Users\Administrator\Desktop\2021-09-30\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\iis\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0217\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0217\x64\Release\demo.pdb"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Administrator\Desktop\2021-09-30\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\iis\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0217\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0217\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0301\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0301\x64\Release\demo.pdb", "C:\Users\Administrator\Desktop\dll0315\Release\demo.pdb") or FileName in~ ("32.dll", "64.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `143.92.36.109`, `38.181.52.147`, `154.23.186.99`, `154.36.149.4`, `45.194.17.133`, `lee.6686ty.vip`, `iis.01nmwe.xyz`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `79b3c217f5b7c257d8c7f4c8166102e9754208e60306aa3f4bf917e765fac8ea`, `d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf`, `80e9a39292b7af7b9831563799776808e597bade3fba4f4d7b25b6833a8c7e5a`, `ff8095aba365885b0886da894794ac45ae5e0c3363a45ae106383e5bd1353941`, `5904b42d8099a6657ea21a6af0ae9bd50ae7ca4b619fee125df133051cff2b8a`, `4091ddc3560fb60bd3ef071367fd833d67c3c6e3e81165aa3d93519b93959658`, `fa15ba707356cb474c16ce04abd86ae9d074763ab965e3766d6af56f37003dda`, `c732067b3d8763c248051366ab7beeae0d7fbe105884d4d3f8647e3427f36daf` _(+22 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
