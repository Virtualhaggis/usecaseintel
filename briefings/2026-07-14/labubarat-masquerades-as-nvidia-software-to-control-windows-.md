# [CRIT] LabubaRAT Masquerades as NVIDIA Software to Control Windows Hosts

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/labubarat-masquerades-as-nvidia.html

## Threat Profile

LabubaRAT Masquerades as NVIDIA Software to Control Windows Hosts 
 Ravie Lakshmanan  Jul 14, 2026 Malware / Threat Intelligence 
Cybersecurity researchers have flagged a previously undocumented Rust-based remote access trojan (RAT) codenamed LabubaRAT that masquerades as NVIDIA software to blend into target environments.
"LabubaRAT creates a reusable foothold for hands-on activity," Blackpoint Cyber researchers Sam Decker and Nevan Beal said in an analysis published today. "Once deployed, it …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `pipicka.xyz`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1140** — Deobfuscate/Decode Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1572** — Protocol Tunneling
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1566.002** — Phishing: Spearphishing Link
- **T1036** — Masquerading
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### LabubaRAT nvidia-sysruntime.exe launch with runtime C2 config in command line

`UC_87_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="nvidia-sysruntime.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| eval c2_config=if(match(process,"(?i)pipicka\.xyz"),"pipicka.xyz",if(match(process,"[A-Za-z0-9+/]{40,}={0,2}"),"base64_arg","none"))
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "nvidia-sysruntime.exe" or ProcessCommandLine has "nvidia-sysruntime"
| extend C2Config = case(ProcessCommandLine has "pipicka.xyz","pipicka.xyz", ProcessCommandLine matches regex @"[A-Za-z0-9+/]{40,}={0,2}","base64_arg","none")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, C2Config, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### LabubaRAT C2 beacon to pipicka.xyz (HTTPS / DNS tunneling) from NVIDIA-impersonating host

`UC_87_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*pipicka.xyz" by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| eval subdomain_len=len(replace(query,"(?i)\.?pipicka\.xyz$",""))
| eval tunneling_suspected=if(subdomain_len>30,"yes","no")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "pipicka.xyz" or RemoteUrl contains ".pipicka.xyz"
| extend Subdomain = tostring(split(RemoteUrl, ".pipicka.xyz")[0])
| extend TunnelingSuspected = iff(strlen(Subdomain) > 30, "yes", "no")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol, TunnelingSuspected
| order by Timestamp desc
```

### NVIDIA-branded process spawns shell / LOLBin (LabubaRAT operator tasking)

`UC_87_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="nvidia*.exe") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName startswith "nvidia" and InitiatingProcessFileName endswith ".exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### NVIDIA-named executable without valid NVIDIA code signature

`UC_87_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="nvidia*.exe") AND NOT (Processes.process_path="*\\Program Files\\NVIDIA*" OR Processes.process_path="*\\Program Files (x86)\\NVIDIA*" OR Processes.process_path="*\\Windows\\System32\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName startswith "nvidia" and FileName endswith ".exe"
| where isempty(ProcessVersionInfoCompanyName) or ProcessVersionInfoCompanyName !has "NVIDIA"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, SHA256, ProcessCommandLine
| order by Timestamp desc
```

### LabubaRAT user-level autostart persistence (Run key / scheduled task referencing NVIDIA loader)

`UC_87_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*") AND (Registry.registry_value_data="*nvidia-sysruntime*" OR Registry.registry_value_data="*pipicka.xyz*") by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueData has "nvidia-sysruntime" or RegistryValueData has "pipicka.xyz" or (InitiatingProcessFileName startswith "nvidia" and InitiatingProcessFileName endswith ".exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### Trojanized NVIDIA installer download from non-NVIDIA source

`UC_87_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="nvidia*.exe") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| search process_name IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe","outlook.exe")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName startswith "nvidia" and FileName endswith ".exe"
| where isnotempty(FileOriginUrl)
| where not(FileOriginUrl has "nvidia.com" or FileOriginUrl has "nvidia.cn" or FileOriginUrl has "download.nvidia.com" or FileOriginUrl has "nvidia.co")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

### NVIDIA-branded process outbound to non-NVIDIA public infrastructure (LabubaRAT C2 / SOCKS5 proxy)

`UC_87_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process="*nvidia*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| iplocation dest
| where isnotnull(dest) AND NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("192.168.0.0/16",dest) AND NOT cidrmatch("172.16.0.0/12",dest)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName startswith "nvidia" and InitiatingProcessFileName endswith ".exe"
| where RemoteIPType == "Public"
| where not(RemoteUrl has "nvidia.com" or RemoteUrl has "nvidia.cn" or RemoteUrl endswith "nvidia.co")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ConnCount=count(), Ports=make_set(RemotePort,10), Urls=make_set(RemoteUrl,10) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP
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

### Article-specific behavioural hunt — LabubaRAT Masquerades as NVIDIA Software to Control Windows Hosts

`UC_87_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — LabubaRAT Masquerades as NVIDIA Software to Control Windows Hosts ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("nvidia-sysruntime.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("nvidia-sysruntime.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — LabubaRAT Masquerades as NVIDIA Software to Control Windows Hosts
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("nvidia-sysruntime.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("nvidia-sysruntime.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `pipicka.xyz`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
