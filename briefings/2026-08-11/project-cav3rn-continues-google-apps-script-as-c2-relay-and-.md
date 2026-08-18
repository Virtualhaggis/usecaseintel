# [HIGH] Project CAV3RN continues: Google Apps Script as C2 relay and DNS-based C2 channel selection

**Source:** Securelist (Kaspersky)
**Published:** 2026-08-11
**Article:** https://securelist.com/project-cav3rn-continues/120991/

## Threat Profile

Table of Contents
Multi-transport C2 communication module 
Google Apps Script channel 
Direct HTTPS channel 
Inter-component DLL broker 
Infrastructure 
Conclusions 
Indicators of compromise 
File hashes 
Domains and IPs 
Authors
GReAT 
Project CAV3RN is a modular espionage framework used against targets in Israel. This report expands on two earlier publications: the first was published in June 2026 as part of our Kaspersky Threat Intelligence Reporting service , and the second was published on …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `12.19.29.30`
- **IPv4 (defanged):** `12.121.234.120`
- **IPv4 (defanged):** `144.172.115.17`
- **IPv4 (defanged):** `144.172.104.82`
- **IPv4 (defanged):** `74.65.75.102`
- **Domain (defanged):** `ycz2.41414141303030.m.studiotikva.com`
- **Domain (defanged):** `q.studiotikva.com`
- **Domain (defanged):** `p.studiotikva.com`
- **Domain (defanged):** `api.studiotikva.com`
- **Domain (defanged):** `studiotikva.com`
- **Domain (defanged):** `ns1.studiotikva.com`
- **Domain (defanged):** `ns2.studiotikva.com`
- **Domain (defanged):** `m.studiotikva.com`
- **Domain (defanged):** `script.googleusercontent.com`
- **MD5:** `904784c9943d019da332bea2cd03996f`
- **MD5:** `f9156d42410c8a5429dec43329bd72e0`
- **MD5:** `2dcd4a8ac166404977cd3c48418a8cd9`
- **MD5:** `981c7404d31b8ce35ec88a6b290f354d`
- **MD5:** `34d50eec364d920b8b5d885c9bc98607`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File

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

### Article-specific behavioural hunt — Project CAV3RN continues: Google Apps Script as C2 relay and DNS-based C2 channe

`UC_91_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Project CAV3RN continues: Google Apps Script as C2 relay and DNS-based C2 channe ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("googleservice.dll","rnp.dll","communicationuxtheme.dll","net.dll","texture.dll") OR Processes.process_path="*C:\Users\user\Desktop\Modules\broker-cavern\communication\GoogleCommunication\bin\Release\net8.0\win-x64\native\GoogleService.pdb*" OR Processes.process_path="*C:\Users\user\Desktop\Modules\broker-cavern\1.out\rnp.pdb*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\user\Desktop\Modules\broker-cavern\communication\GoogleCommunication\bin\Release\net8.0\win-x64\native\GoogleService.pdb*" OR Filesystem.file_path="*C:\Users\user\Desktop\Modules\broker-cavern\1.out\rnp.pdb*" OR Filesystem.file_name IN ("googleservice.dll","rnp.dll","communicationuxtheme.dll","net.dll","texture.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Project CAV3RN continues: Google Apps Script as C2 relay and DNS-based C2 channe
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("googleservice.dll", "rnp.dll", "communicationuxtheme.dll", "net.dll", "texture.dll") or FolderPath has_any ("C:\Users\user\Desktop\Modules\broker-cavern\communication\GoogleCommunication\bin\Release\net8.0\win-x64\native\GoogleService.pdb", "C:\Users\user\Desktop\Modules\broker-cavern\1.out\rnp.pdb"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\user\Desktop\Modules\broker-cavern\communication\GoogleCommunication\bin\Release\net8.0\win-x64\native\GoogleService.pdb", "C:\Users\user\Desktop\Modules\broker-cavern\1.out\rnp.pdb") or FileName in~ ("googleservice.dll", "rnp.dll", "communicationuxtheme.dll", "net.dll", "texture.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `12.19.29.30`, `12.121.234.120`, `144.172.115.17`, `144.172.104.82`, `74.65.75.102`, `ycz2.41414141303030.m.studiotikva.com`, `q.studiotikva.com`, `p.studiotikva.com` _(+6 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `904784c9943d019da332bea2cd03996f`, `f9156d42410c8a5429dec43329bd72e0`, `2dcd4a8ac166404977cd3c48418a8cd9`, `981c7404d31b8ce35ec88a6b290f354d`, `34d50eec364d920b8b5d885c9bc98607`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
