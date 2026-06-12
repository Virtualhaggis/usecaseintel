# [CRIT] OceanLotus: From external espionage to domestic targeting

**Source:** ESET WeLiveSecurity
**Published:** 2026-06-11
**Article:** https://www.welivesecurity.com/en/eset-research/oceanlotus-external-espionage-domestic-targeting/

## Threat Profile

OceanLotus: From external espionage to domestic targeting 
ESET Research
OceanLotus: From external espionage to domestic targeting A shift in operational pattern of the infamous Vietnam-aligned APT group
ESET Research 
11 Jun 2026 
 •  
, 
14 min. read 
Our tracking of OceanLotus activities from 2024–2026 reveals a shift in operational focus. During this period, the Vietnam-aligned OceanLotus adopted a more selective approach to external operations while placing increasing emphasis on domestic e…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `139.162.11.152`
- **IPv4 (defanged):** `142.91.98.77`
- **IPv4 (defanged):** `139.180.128.42`
- **IPv4 (defanged):** `139.99.33.239`
- **IPv4 (defanged):** `166.88.77.186`
- **IPv4 (defanged):** `103.119.47.104`
- **IPv4 (defanged):** `38.60.245.37`
- **IPv4 (defanged):** `194.68.26.241`
- **Domain (defanged):** `financemachinelearning.com`
- **Domain (defanged):** `gatewayrvcenter.com`
- **Domain (defanged):** `coachcybersecurity.com`
- **Domain (defanged):** `mxprodesign.com`
- **Domain (defanged):** `power-sync-services.com`
- **Domain (defanged):** `leadingfilipinoteams.com`
- **SHA1:** `D511B77459673EC42163F19E300FF1D233B6C39F`
- **SHA1:** `59A8553A4F8130F576AB234E0B220BE4D4DA0E98`
- **SHA1:** `9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD`
- **SHA1:** `A8E2BBBFCB86500322D2367744FA12755AB0C165`
- **SHA1:** `F74F1FEB62B662CDA489FDB2453727824E55ACB9`
- **SHA1:** `F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9`
- **SHA1:** `19A69F856EFA811C376F68E4FEB0997B4724F8BD`
- **SHA1:** `490194E9BB5128ECA8693AD9E610891C2ED185AF`
- **SHA1:** `51176139B0B2220B802C1578A4994DF68DF5BCD1`
- **SHA1:** `91F042F59BE4BDCB6E5EA21B91DECD731C175B54`
- **SHA1:** `A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D`
- **SHA1:** `B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48`
- **SHA1:** `4AD36AD6C165B5174967020CB1A3358F78D7A283`
- **SHA1:** `57352B3CEEE32216E5AA20BAA848483D7AB5A6FB`
- **SHA1:** `9BC06DF9F932746A05EE728C8B103BD3BA6BF395`
- **SHA1:** `865A1739337D3303B3AB02C5E694C22B79C42B7D`
- **SHA1:** `41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0`
- **SHA1:** `0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20`
- **SHA1:** `5D6194BB48FEBB91A10D1462461A012FAFC0918B`
- **SHA1:** `B028E947150764A71DEEF498DE6F8C95ECCCB445`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1059** — Command and Scripting Interpreter
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1573** — Encrypted Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OceanLotus SPECTRALVIPER C2 callback to known infrastructure (IPs + domains)

`UC_34_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241") by All_Traffic.src All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src from datamodel=Network_Resolution.DNS where DNS.query IN ("financemachinelearning.com","gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","leadingfilipinoteams.com","*.financemachinelearning.com","*.gatewayrvcenter.com","*.coachcybersecurity.com","*.mxprodesign.com","*.power-sync-services.com","*.leadingfilipinoteams.com") by DNS.query DNS.src | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let OceanLotusIPs = dynamic(["139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241"]);
let OceanLotusDomains = dynamic(["financemachinelearning.com","gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","leadingfilipinoteams.com"]);
union
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteIP in (OceanLotusIPs) or RemoteUrl has_any (OceanLotusDomains)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort, Source="DeviceNetworkEvents"
),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | extend Q = tostring(parse_json(AdditionalFields).query)
  | where Q has_any (OceanLotusDomains) or RemoteUrl has_any (OceanLotusDomains)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl=coalesce(RemoteUrl,Q), RemotePort, Source="DnsQueryResponse"
)
| order by Timestamp desc
```

### SPECTRALVIPER known-bad SHA1 hash on file write or process execution

`UC_34_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("d511b77459673ec42163f19e300ff1d233b6c39f","59a8553a4f8130f576ab234e0b220be4d4da0e98","9ca1a5c7f79882db913534c1e62b26bcdcb9f6dd","a8e2bbbfcb86500322d2367744fa12755ab0c165","f74f1feb62b662cda489fdb2453727824e55acb9","f8f8209987ca7f139de6a62f9e6ee21bd2ae93a9","19a69f856efa811c376f68e4feb0997b4724f8bd","490194e9bb5128eca8693ad9e610891c2ed185af","51176139b0b2220b802c1578a4994df68df5bcd1","91f042f59be4bdcb6e5ea21b91decd731c175b54","a177ed0bffeb1efe1d9d31d72a82ef2625ae646d","b7b2d2db544f9eea74453cdf2b8beea58cf07c48","4ad36ad6c165b5174967020cb1a3358f78d7a283","57352b3ceee32216e5aa20baa848483d7ab5a6fb","9bc06df9f932746a05ee728c8b103bd3ba6bf395","865a1739337d3303b3ab02c5e694c22b79c42b7d","41cb8cd78b8db76563e4f972abe817ceee9cf9b0","0037dbb0fea981d02f6f76de81ebaefcb68b7d20","5d6194bb48febb91a10d1462461a012fafc0918b","b028e947150764a71deef498de6f8c95ecccb445") by host Processes.process_name Processes.process_hash Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let OceanLotusSHA1 = dynamic(["d511b77459673ec42163f19e300ff1d233b6c39f","59a8553a4f8130f576ab234e0b220be4d4da0e98","9ca1a5c7f79882db913534c1e62b26bcdcb9f6dd","a8e2bbbfcb86500322d2367744fa12755ab0c165","f74f1feb62b662cda489fdb2453727824e55acb9","f8f8209987ca7f139de6a62f9e6ee21bd2ae93a9","19a69f856efa811c376f68e4feb0997b4724f8bd","490194e9bb5128eca8693ad9e610891c2ed185af","51176139b0b2220b802c1578a4994df68df5bcd1","91f042f59be4bdcb6e5ea21b91decd731c175b54","a177ed0bffeb1efe1d9d31d72a82ef2625ae646d","b7b2d2db544f9eea74453cdf2b8beea58cf07c48","4ad36ad6c165b5174967020cb1a3358f78d7a283","57352b3ceee32216e5aa20baa848483d7ab5a6fb","9bc06df9f932746a05ee728c8b103bd3ba6bf395","865a1739337d3303b3ab02c5e694c22b79c42b7d","41cb8cd78b8db76563e4f972abe817ceee9cf9b0","0037dbb0fea981d02f6f76de81ebaefcb68b7d20","5d6194bb48febb91a10d1462461a012fafc0918b","b028e947150764a71deef498de6f8c95ecccb445"]);
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (OceanLotusSHA1) or InitiatingProcessSHA1 in (OceanLotusSHA1)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA1, Source="DeviceProcessEvents"
),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (OceanLotusSHA1) or InitiatingProcessSHA1 in (OceanLotusSHA1)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA1, Source="DeviceFileEvents"
),
( DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (OceanLotusSHA1)
  | project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DeviceImageLoadEvents"
)
| order by Timestamp desc
```

### FireAnt Metakit updater spawning script/LOLBin or writing PE to user-writable path (supply-chain)

`UC_34_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as child_path from datamodel=Endpoint.Processes where (Processes.parent_process_name="FireAnt.exe" OR Processes.parent_process_name="FireAntMetakit.exe" OR Processes.parent_process="*\\FireAnt*\\*" OR Processes.parent_process="*Metakit*") AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msiexec.exe")) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where (Filesystem.process_name="FireAnt.exe" OR Filesystem.process_name="FireAntMetakit.exe") AND (Filesystem.file_name="*.exe" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.scr") AND (Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\Temp\\*") by host Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let FireAntParents = dynamic(["fireant.exe","fireantmetakit.exe","metakit.exe","fireant_updater.exe","fireantupdater.exe"]);
let SuspChildren = dynamic(["powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msiexec.exe"]);
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where InitiatingProcessFileName in~ (FireAntParents) or InitiatingProcessFolderPath has_any ("FireAnt","Metakit")
  | where FileName in~ (SuspChildren)
  | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA1, Pivot="FireAnt_child_lolbin"
),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where InitiatingProcessFileName in~ (FireAntParents) or InitiatingProcessFolderPath has_any ("FireAnt","Metakit")
  | where ActionType in ("FileCreated","FileRenamed")
  | where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr" or FileName endswith ".lnk"
  | where FolderPath has_any (@"\AppData\",@"\ProgramData\",@"\Temp\",@"\Public\")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA1, SHA256, Pivot="FireAnt_drops_PE"
)
| order by Timestamp desc
```

### Sustained low-rate beaconing from single host to OceanLotus C2 IP set (long-tail intrusion signal)

`UC_34_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as conn_count min(_time) as firstTime max(_time) as lastTime dc(eval(strftime(_time,"%Y-%m-%d-%H"))) as distinct_hours dc(eval(strftime(_time,"%Y-%m-%d"))) as distinct_days values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241") by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | where distinct_days >= 3 AND distinct_hours >= 6 | eval avg_per_day=round(conn_count/distinct_days,2) | convert ctime(firstTime) ctime(lastTime) | sort - distinct_days
```

**Defender KQL:**
```kql
let OceanLotusIPs = dynamic(["139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (OceanLotusIPs)
| extend HourBucket = bin(Timestamp, 1h), DayBucket = startofday(Timestamp)
| summarize ConnCount = count(),
            DistinctHours = dcount(HourBucket),
            DistinctDays = dcount(DayBucket),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Ports = make_set(RemotePort, 20),
            Processes = make_set(InitiatingProcessFileName, 20),
            CmdSamples = make_set(InitiatingProcessCommandLine, 10)
            by DeviceName, RemoteIP
| where DistinctDays >= 3 and DistinctHours >= 6
| extend CampaignSpanDays = datetime_diff('day', LastSeen, FirstSeen)
| order by DistinctDays desc, CampaignSpanDays desc
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — OceanLotus: From external espionage to domestic targeting

`UC_34_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — OceanLotus: From external espionage to domestic targeting ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("metakit.exe","dtlcrashcatch.dll","intelaudioservice.exe","dtlupdate.exe","onedrive.sync.service.exe","genuine.exe","updater.exe","autocad242.exe","toolbox.exe","setupui.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("metakit.exe","dtlcrashcatch.dll","intelaudioservice.exe","dtlupdate.exe","onedrive.sync.service.exe","genuine.exe","updater.exe","autocad242.exe","toolbox.exe","setupui.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — OceanLotus: From external espionage to domestic targeting
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("metakit.exe", "dtlcrashcatch.dll", "intelaudioservice.exe", "dtlupdate.exe", "onedrive.sync.service.exe", "genuine.exe", "updater.exe", "autocad242.exe", "toolbox.exe", "setupui.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("metakit.exe", "dtlcrashcatch.dll", "intelaudioservice.exe", "dtlupdate.exe", "onedrive.sync.service.exe", "genuine.exe", "updater.exe", "autocad242.exe", "toolbox.exe", "setupui.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `139.162.11.152`, `142.91.98.77`, `139.180.128.42`, `139.99.33.239`, `166.88.77.186`, `103.119.47.104`, `38.60.245.37`, `194.68.26.241` _(+6 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `D511B77459673EC42163F19E300FF1D233B6C39F`, `59A8553A4F8130F576AB234E0B220BE4D4DA0E98`, `9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD`, `A8E2BBBFCB86500322D2367744FA12755AB0C165`, `F74F1FEB62B662CDA489FDB2453727824E55ACB9`, `F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9`, `19A69F856EFA811C376F68E4FEB0997B4724F8BD`, `490194E9BB5128ECA8693AD9E610891C2ED185AF` _(+12 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
