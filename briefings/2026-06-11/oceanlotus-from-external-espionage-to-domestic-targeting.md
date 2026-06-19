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
- **T1218.011** — Rundll32
- **T1055** — Process Injection
- **T1574.002** — DLL Side-Loading
- **T1572** — Protocol Tunneling
- **T1132.001** — Standard Encoding
- **T1095** — Non-Application Layer Protocol
- **T1562.008** — Impair Defenses: Disable or Modify Cloud Logs
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OceanLotus SPECTRALVIPER C2 network communication (known domains/IPs)

`UC_156_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241") OR All_Traffic.dest IN ("financemachinelearning.com","gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","leadingfilipinoteams.com") by All_Traffic.src, All_Traffic.user, All_Traffic.dest, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let cnc_domains = dynamic(["financemachinelearning.com","gatewayrvcenter.com","coachcybersecurity.com","mxprodesign.com","power-sync-services.com","leadingfilipinoteams.com"]);
let cnc_ips = dynamic(["139.162.11.152","142.91.98.77","139.180.128.42","139.99.33.239","166.88.77.186","103.119.47.104","38.60.245.37","194.68.26.241"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (cnc_ips) or RemoteUrl has_any (cnc_domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol, ActionType
| order by Timestamp desc
```

### FireAnt Metakit updater spawning unexpected interpreter/LOLBin children (supply-chain payload exec)

`UC_156_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="FireAnt*" OR Processes.parent_process_name="fireant*" OR Processes.parent_process="*\\FireAnt*" OR Processes.parent_process="*Metakit*") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(180d)
| where InitiatingProcessFileName has_any ("FireAnt", "fireant", "Metakit", "metakit")
    or InitiatingProcessFolderPath has_any (@"\FireAnt\", @"\Metakit\")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","msbuild.exe","installutil.exe")
    or (FolderPath has_any (@"\AppData\", @"\ProgramData\", @"\Users\Public\", @"\Temp\") and FileName endswith ".exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA1, SHA256
| order by Timestamp desc
```

### Known SPECTRALVIPER / OceanLotus SHA1 hash execution or write

`UC_156_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("D511B77459673EC42163F19E300FF1D233B6C39F","59A8553A4F8130F576AB234E0B220BE4D4DA0E98","9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD","A8E2BBBFCB86500322D2367744FA12755AB0C165","F74F1FEB62B662CDA489FDB2453727824E55ACB9","F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9","19A69F856EFA811C376F68E4FEB0997B4724F8BD","490194E9BB5128ECA8693AD9E610891C2ED185AF","51176139B0B2220B802C1578A4994DF68DF5BCD1","91F042F59BE4BDCB6E5EA21B91DECD731C175B54","A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D","B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48","4AD36AD6C165B5174967020CB1A3358F78D7A283","57352B3CEEE32216E5AA20BAA848483D7AB5A6FB","9BC06DF9F932746A05EE728C8B103BD3BA6BF395","865A1739337D3303B3AB02C5E694C22B79C42B7D","41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0","0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20","5D6194BB48FEBB91A10D1462461A012FAFC0918B","B028E947150764A71DEEF498DE6F8C95ECCCB445") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badhashes = dynamic(["D511B77459673EC42163F19E300FF1D233B6C39F","59A8553A4F8130F576AB234E0B220BE4D4DA0E98","9CA1A5C7F79882DB913534C1E62B26BCDCB9F6DD","A8E2BBBFCB86500322D2367744FA12755AB0C165","F74F1FEB62B662CDA489FDB2453727824E55ACB9","F8F8209987CA7F139DE6A62F9E6EE21BD2AE93A9","19A69F856EFA811C376F68E4FEB0997B4724F8BD","490194E9BB5128ECA8693AD9E610891C2ED185AF","51176139B0B2220B802C1578A4994DF68DF5BCD1","91F042F59BE4BDCB6E5EA21B91DECD731C175B54","A177ED0BFFEB1EFE1D9D31D72A82EF2625AE646D","B7B2D2DB544F9EEA74453CDF2B8BEEA58CF07C48","4AD36AD6C165B5174967020CB1A3358F78D7A283","57352B3CEEE32216E5AA20BAA848483D7AB5A6FB","9BC06DF9F932746A05EE728C8B103BD3BA6BF395","865A1739337D3303B3AB02C5E694C22B79C42B7D","41CB8CD78B8DB76563E4F972ABE817CEEE9CF9B0","0037DBB0FEA981D02F6F76DE81EBAEFCB68B7D20","5D6194BB48FEBB91A10D1462461A012FAFC0918B","B028E947150764A71DEEF498DE6F8C95ECCCB445"]);
union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(365d) | where SHA1 in (badhashes) or InitiatingProcessSHA1 in (badhashes) | project Timestamp, Table="Process", DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA1, InitiatingProcessFileName, InitiatingProcessSHA1),
(DeviceFileEvents | where Timestamp > ago(365d) | where SHA1 in (badhashes) | project Timestamp, Table="FileWrite", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA1, InitiatingProcessFileName, InitiatingProcessSHA1),
(DeviceImageLoadEvents | where Timestamp > ago(365d) | where SHA1 in (badhashes) | project Timestamp, Table="ImageLoad", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA1, InitiatingProcessFileName, InitiatingProcessSHA1=InitiatingProcessSHA1)
| order by Timestamp desc
```

### OceanLotus Denis/SOUNDBITE DNS tunneling — high-entropy long subdomain bursts

`UC_156_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where DNS.record_type IN ("A","AAAA","TXT") by DNS.src, DNS.query, DNS.record_type, _time | `drop_dm_object_name(DNS)` | rex field=query "^(?<sub>[^.]+)\.(?<parent>.+)$" | eval sub_len=len(sub) | eval label_entropy=if(sub_len>0, round(len(replace(sub,"[^a-zA-Z0-9]",""))/sub_len,2), 0) | where sub_len >= 30 | bin _time span=5m | stats count as qcount dc(query) as unique_q max(sub_len) as max_label by _time, src, parent | where qcount > 30 and unique_q > 20 | sort -_time
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend Query = tostring(parse_json(AdditionalFields).Query)
| where isnotempty(Query)
| extend Label = tostring(split(Query, ".")[0])
| extend LabelLen = strlen(Label)
| extend Parent = strcat_array(array_slice(split(Query, "."), 1, -1), ".")
| where LabelLen >= 30
| summarize QueryCount = count(), UniqueLabels = dcount(Label), MaxLabelLen = max(LabelLen), SampleQuery = any(Query)
          by bin(Timestamp, 5m), DeviceName, InitiatingProcessFileName, Parent
| where QueryCount > 30 and UniqueLabels > 20
| order by Timestamp desc
```

### OceanLotus PHOREAL ICMP C&C beaconing from workstations

`UC_156_13` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dests from datamodel=Network_Traffic.All_Traffic where All_Traffic.transport="icmp" AND All_Traffic.dest_category!="internal" by All_Traffic.src, All_Traffic.app, All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | where count > 50 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol =~ "Icmp"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("ping.exe","PathPing.exe","tracert.exe","mtr.exe","system")
| summarize PacketCount = count(),
            DistinctMinutes = dcount(bin(Timestamp, 1m)),
            DistinctDestinations = dcount(RemoteIP),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleDest = any(RemoteIP),
            SampleProc = any(InitiatingProcessCommandLine)
          by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName
| where PacketCount > 50 and DistinctMinutes > 20
| order by PacketCount desc
```

### OceanLotus WINDSHIELD proxy bypass — direct outbound HTTP(S) from non-browser process

`UC_156_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dests from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (80,443,8080,8443) AND All_Traffic.dest_category!="internal" AND NOT All_Traffic.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","outlook.exe","teams.exe","OneDrive.exe","OneNote.exe","slack.exe","zoom.exe","webexmta.exe","MsSense.exe","MsMpEng.exe","svchost.exe","backgroundtaskhost.exe","WindowsUpdate.exe","wuauclt.exe","vpnui.exe","openvpn.exe") by All_Traffic.src, All_Traffic.user, All_Traffic.process_name, All_Traffic.process, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where count > 10 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let proxy_aware = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","outlook.exe","teams.exe","OneDrive.exe","OneNote.exe","slack.exe","zoom.exe","webex.exe","MsSense.exe","MsMpEng.exe","svchost.exe","backgroundtaskhost.exe","vpnui.exe","openvpn.exe","WindowsUpdate.exe","wuauclt.exe","MoUsoCoreWorker.exe","SearchHost.exe"]);
let direct_egress = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteIPType == "Public"
    | where RemotePort in (80, 443, 8080, 8443)
    | where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
    | where InitiatingProcessFileName !in~ (proxy_aware)
    | where InitiatingProcessAccountName !endswith "$"
    | summarize ConnCount = count(), DistinctIPs = dcount(RemoteIP), DistinctMin = dcount(bin(Timestamp, 1m)), SampleIP = any(RemoteIP), SampleUrl = any(RemoteUrl)
              by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
    | where ConnCount > 10;
let pac_tamper = DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Internet Settings"
    | where RegistryValueName in ("ProxyEnable","ProxyServer","AutoConfigURL","ProxyOverride")
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData;
union direct_egress, pac_tamper
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

`UC_156_8` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
