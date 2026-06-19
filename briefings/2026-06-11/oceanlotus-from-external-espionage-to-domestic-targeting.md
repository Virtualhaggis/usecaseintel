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
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1218** — System Binary Proxy Execution
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1572** — Protocol Tunneling
- **T1095** — Non-Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound to OceanLotus C&C IP infrastructure (Vultr/Choopa cluster)

`UC_155_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241") by All_Traffic.dest All_Traffic.src host | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let OceanLotusIPs = dynamic(["139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (OceanLotusIPs)
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol, ActionType
| order by Timestamp desc
```

### DNS resolution of OceanLotus SPECTRALVIPER C&C domains

`UC_155_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src from datamodel=Network_Resolution.DNS where DNS.query IN ("gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","financemachinelearning.com","leadingfilipinoteams.com","*.gatewayrvcenter.com","*.coachcybersecurity.com","*.mxprodesign.com","*.power-sync-services.com","*.financemachinelearning.com","*.leadingfilipinoteams.com") by DNS.query DNS.src host | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let OceanLotusDomains = dynamic(["gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","financemachinelearning.com","leadingfilipinoteams.com"]);
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| extend QueriedDomain = tolower(tostring(parse_json(AdditionalFields).DnsQueryName))
| where QueriedDomain in (OceanLotusDomains) or QueriedDomain endswith ".gatewayrvcenter.com" or QueriedDomain endswith ".coachcybersecurity.com" or QueriedDomain endswith ".mxprodesign.com" or QueriedDomain endswith ".power-sync-services.com" or QueriedDomain endswith ".financemachinelearning.com" or QueriedDomain endswith ".leadingfilipinoteams.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, QueriedDomain
| order by Timestamp desc
```

### Known SPECTRALVIPER SHA1 hash execution / file-write

`UC_155_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_sha1 IN ("D511B77459673EC42163F19E300FF1D233B6C39F","59A8553A4F8130F576AB234E0B220BE4D4DA0E98","9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD","A8E2BBBFCB86500322D2367744FA12755AB0C165","F74F1FEB62B662CDA489FDB2453727824E55ACB9","F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9","19A69F856EFA811C376F68E4FEB0997B4724F8BD","490194E9BB5128ECA8693AD9E610891C2ED185AF","51176139B0B2220B802C1578A4994DF68DF5BCD1","91F042F59BE4BDCB6E5EA21B91DECD731C175B54","A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D","B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48","4AD36AD6C165B5174967020CB1A3358F78D7A283","57352B3CEEE32216E5AA20BAA848483D7AB5A6FB","9BC06DF9F932746A05EE728C8B103BD3BA6BF395","865A1739337D3303B3AB02C5E694C22B79C42B7D","41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0","0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20","5D6194BB48FEBB91A10D1462461A012FAFC0918B","B028E947150764A71DEEF498DE6F8C95ECCCB445") by host Processes.user Processes.process_name Processes.process_sha1 | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SVHashes = dynamic(["D511B77459673EC42163F19E300FF1D233B6C39F","59A8553A4F8130F576AB234E0B220BE4D4DA0E98","9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD","A8E2BBBFCB86500322D2367744FA12755AB0C165","F74F1FEB62B662CDA489FDB2453727824E55ACB9","F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9","19A69F856EFA811C376F68E4FEB0997B4724F8BD","490194E9BB5128ECA8693AD9E610891C2ED185AF","51176139B0B2220B802C1578A4994DF68DF5BCD1","91F042F59BE4BDCB6E5EA21B91DECD731C175B54","A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D","B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48","4AD36AD6C165B5174967020CB1A3358F78D7A283","57352B3CEEE32216E5AA20BAA848483D7AB5A6FB","9BC06DF9F932746A05EE728C8B103BD3BA6BF395","865A1739337D3303B3AB02C5E694C22B79C42B7D","41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0","0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20","5D6194BB48FEBB91A10D1462461A012FAFC0918B","B028E947150764A71DEEF498DE6F8C95ECCCB445"]);
union isfuzzy=true
  (DeviceProcessEvents | where Timestamp > ago(90d) | where SHA1 in (SVHashes) | project Timestamp, Source="Process", DeviceName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName),
  (DeviceFileEvents | where Timestamp > ago(90d) | where SHA1 in (SVHashes) | project Timestamp, Source="FileWrite", DeviceName, FileName, FolderPath, SHA1, ProcessCommandLine="", InitiatingProcessFileName),
  (DeviceImageLoadEvents | where Timestamp > ago(90d) | where SHA1 in (SVHashes) | project Timestamp, Source="ImageLoad", DeviceName, FileName, FolderPath, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName)
| order by Timestamp desc
```

### FireAnt Metakit update process spawns LOLBin or unsigned child

`UC_155_12` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.parent_process_path="*\\FireAnt*" OR Processes.parent_process_name="FireAnt*.exe" OR Processes.parent_process_path="*\\Metakit*") (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","curl.exe","certutil.exe","bitsadmin.exe") OR Processes.process_path IN ("*\\AppData\\Local\\Temp\\*","*\\AppData\\Roaming\\*","*\\ProgramData\\*")) by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has "fireant" or InitiatingProcessFolderPath has "FireAnt" or InitiatingProcessFolderPath has "Metakit" or InitiatingProcessCommandLine has "Metakit"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","curl.exe","certutil.exe","bitsadmin.exe","installutil.exe","msbuild.exe") 
   or FolderPath startswith @"C:\Users\" and (FolderPath has @"\AppData\Local\Temp\" or FolderPath has @"\AppData\Roaming\")
   or FolderPath startswith @"C:\ProgramData\"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### SPECTRALVIPER orchestrator persistence – scheduled task / Run key write by FireAnt-tree process

`UC_155_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as data from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" (Registry.registry_value_data="*\\AppData\\*" OR Registry.registry_value_data="*\\ProgramData\\*" OR Registry.registry_value_data="*\\Public\\*") by host Registry.user Registry.registry_key_name Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RunKeys = dynamic([@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce"]);
let RegPersist = DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has_any (RunKeys) or RegistryKey has @"\Services\"
    | where RegistryValueData has_any (@"\AppData\", @"\ProgramData\", @"\Public\", @"\Users\Public\")
           or InitiatingProcessFolderPath has "FireAnt" or InitiatingProcessFileName has "fireant"
    | extend Persistence="RunKey"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Persistence, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine;
let SchedTasks = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "schtasks.exe" and ProcessCommandLine has_any ("/create","/CREATE")
    | where ProcessCommandLine has_any (@"\AppData\", @"\ProgramData\", @"\Public\", "powershell", "rundll32", "regsvr32", "FireAnt", "Metakit")
    | extend Persistence="SchTask"
    | project Timestamp, DeviceName, AccountName, Persistence, RegistryKey="", RegistryValueName="", RegistryValueData=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine;
union RegPersist, SchedTasks
| where AccountName !endswith "$"
| order by Timestamp desc
```

### Denis/SOUNDBITE DNS tunneling – high-entropy / long-label DNS from endpoint

`UC_155_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query!="" by DNS.query DNS.src host _time span=1h | rex field=DNS.query "^(?<sub>[^.]+)\.(?<parent>.+)$" | eval sub_len=len(sub) | where sub_len>=30 | stats count as qcount dc(sub) as unique_subs values(sub) as samples by host DNS.src parent | where qcount>=20 AND unique_subs>=15
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "DnsQueryResponse"
| extend q = tolower(tostring(parse_json(AdditionalFields).DnsQueryName))
| where isnotempty(q)
| extend sub = tostring(split(q,".")[0]), parent = strcat_array(array_slice(split(q,"."),1, -1), ".")
| where strlen(sub) >= 30
| summarize Queries=count(), DistinctSubs=dcount(sub), SampleSubs=make_set(sub, 5), Process=any(InitiatingProcessFileName) by DeviceName, parent, bin(Timestamp, 1h)
| where Queries >= 20 and DistinctSubs >= 15
| order by Queries desc
```

### Sustained outbound ICMP to public IP from endpoint (PHOREAL covert C&C)

`UC_155_15` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.transport="icmp" All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.dest All_Traffic.app host | `drop_dm_object_name(All_Traffic)` | where count>=100 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where Protocol == "Icmp"
| where RemoteIPType == "Public"
| summarize PacketCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Process=any(InitiatingProcessFileName), ProcCmd=any(InitiatingProcessCommandLine) by DeviceName, RemoteIP
| where PacketCount >= 100
| order by PacketCount desc
```

### Defender-XDR aggregated alert evidence ties device to OceanLotus IOC

`UC_155_16` · phase: **actions** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
let OceanLotusIPs = dynamic(["139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241"]);
let OceanLotusDomains = dynamic(["gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","financemachinelearning.com","leadingfilipinoteams.com"]);
let SVHashes = dynamic(["D511B77459673EC42163F19E300FF1D233B6C39F","59A8553A4F8130F576AB234E0B220BE4D4DA0E98","9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD","A8E2BBBFCB86500322D2367744FA12755AB0C165","F74F1FEB62B662CDA489FDB2453727824E55ACB9","F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9","19A69F856EFA811C376F68E4FEB0997B4724F8BD","490194E9BB5128ECA8693AD9E610891C2ED185AF","51176139B0B2220B802C1578A4994DF68DF5BCD1","91F042F59BE4BDCB6E5EA21B91DECD731C175B54","A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D","B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48","4AD36AD6C165B5174967020CB1A3358F78D7A283","57352B3CEEE32216E5AA20BAA848483D7AB5A6FB","9BC06DF9F932746A05EE728C8B103BD3BA6BF395","865A1739337D3303B3AB02C5E694C22B79C42B7D","41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0","0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20","5D6194BB48FEBB91A10D1462461A012FAFC0918B","B028E947150764A71DEEF498DE6F8C95ECCCB445"]);
AlertEvidence
| where Timestamp > ago(90d)
| where RemoteIP in (OceanLotusIPs) 
   or SHA1 in (SVHashes)
   or (isnotempty(RemoteUrl) and (RemoteUrl has_any (OceanLotusDomains)))
| join kind=leftouter (AlertInfo | project AlertId, Title, Category, Severity, AttackTechniques) on AlertId
| project Timestamp, AlertId, Title, Severity, Category, AttackTechniques, DeviceName, EntityType, FileName, SHA1, RemoteIP, RemoteUrl, AccountName, AccountUpn
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

`UC_155_8` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
