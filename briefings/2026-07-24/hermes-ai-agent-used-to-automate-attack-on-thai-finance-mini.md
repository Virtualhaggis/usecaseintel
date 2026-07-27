# [HIGH] Hermes AI agent used to automate attack on Thai Finance Ministry

**Source:** BleepingComputer
**Published:** 2026-07-24
**Article:** https://www.bleepingcomputer.com/news/security/hermes-ai-agent-used-to-automate-attack-on-thai-finance-ministry/

## Threat Profile

Hermes AI agent used to automate attack on Thai Finance Ministry 
By Lawrence Abrams 
July 24, 2026
03:09 PM
0 
A threat actor used the open-source Hermes AI agent in unattended "YOLO" mode to automate post-exploitation activity during an alleged breach of Thailand's Ministry of Finance.
The activity was uncovered by threat intelligence company Hunt.io and security researcher Bob Diachenko after they discovered several exposed web directories containing hundreds of files associated with the oper…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-3156`
- **CVE:** `CVE-2021-4034`
- **CVE:** `CVE-2017-7269`
- **CVE:** `CVE-2026-43503`
- **CVE:** `CVE-2026-31431`
- **CVE:** `CVE-2026-43284`
- **CVE:** `CVE-2026-43500`
- **IPv4 (defanged):** `43.246.208.207`
- **IPv4 (defanged):** `103.97.0.57`
- **IPv4 (defanged):** `118.107.222.232`
- **IPv4 (defanged):** `202.181.27.115`
- **Domain (defanged):** `redhatupdating432.dnsrd.com`
- **SHA256:** `0f8c905aa25c86f85454acb7e77bf5c50220c2a82e5b69a33741e55c8a85f2fc`
- **SHA256:** `a9447ae174f4aa54f760b7d7cc985c1a970f31e151d3ff66fac247f99ba1b509`
- **SHA256:** `ec7e9ab43a0cc65d29f0b84a93ba88c43d01fed3dec5c968525dc73c03cbfda2`
- **SHA256:** `b65b7ede835ebba36294d52d7780065523340ee09bb8b209ef2dc495e53dfd53`
- **SHA256:** `d252ee7b348b7e43e432d8fb154465838f5cd5fb564905323460e6f0a0c7d1e2`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1105** — Ingress Tool Transfer
- **T1587.001** — Develop Capabilities: Malware
- **T1082** — System Information Discovery
- **T1083** — File and Directory Discovery
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1068** — Exploitation for Privilege Escalation
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Hades Go implant C2 beacon to redhatupdating432.dnsrd.com and Hunt.io-named IPs

`UC_37_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("43.246.208.207","103.97.0.57","118.107.222.232","202.181.27.115") OR All_Traffic.dest IN ("redhatupdating432.dnsrd.com")) by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let c2Domains = dynamic(["redhatupdating432.dnsrd.com"]);
let c2IPs = dynamic(["43.246.208.207","103.97.0.57","118.107.222.232","202.181.27.115"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2IPs) or RemoteUrl in~ (c2Domains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessSHA256
| order by Timestamp desc
```

### Hades Go implant payload written or executed (SHA256 match)

`UC_37_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("0f8c905aa25c86f85454acb7e77bf5c50220c2a82e5b69a33741e55c8a85f2fc","a9447ae174f4aa54f760b7d7cc985c1a970f31e151d3ff66fac247f99ba1b509","ec7e9ab43a0cc65d29f0b84a93ba88c43d01fed3dec5c968525dc73c03cbfda2","b65b7ede835ebba36294d52d7780065523340ee09bb8b209ef2dc495e53dfd53","d252ee7b348b7e43e432d8fb154465838f5cd5fb564905323460e6f0a0c7d1e2") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let hades = dynamic(["0f8c905aa25c86f85454acb7e77bf5c50220c2a82e5b69a33741e55c8a85f2fc","a9447ae174f4aa54f760b7d7cc985c1a970f31e151d3ff66fac247f99ba1b509","ec7e9ab43a0cc65d29f0b84a93ba88c43d01fed3dec5c968525dc73c03cbfda2","b65b7ede835ebba36294d52d7780065523340ee09bb8b209ef2dc495e53dfd53","d252ee7b348b7e43e432d8fb154465838f5cd5fb564905323460e6f0a0c7d1e2"]);
union
(DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in (hades) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in (hades) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Customized LinPEAS privilege-escalation enumeration on Linux host

`UC_37_10` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*linpeas*" OR (Processes.process_name="find" AND (Processes.process="*-perm -4000*" OR Processes.process="*-perm -u=s*" OR Processes.process="*-perm -2000*" OR Processes.process="*-perm -g=s*"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has "linpeas"
   or (FileName == "find" and ProcessCommandLine has_any ("-perm -4000","-perm -2000","-perm -u=s","-perm -g=s"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Linux local privilege escalation attempt (PwnKit CVE-2021-4034 / Baron Samedit CVE-2021-3156)

`UC_37_11` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="pkexec" AND NOT Processes.process="* *") OR (Processes.process_name="sudoedit" AND Processes.process="*-s*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where (FileName =~ "pkexec" and ProcessCommandLine !contains " ")
   or (FileName =~ "sudoedit" and ProcessCommandLine has "-s")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, ProcessIntegrityLevel
| order by Timestamp desc
```

### Web/app-server process spawning shell (PHP web shell / suo5 HTTP tunnel)

`UC_37_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.parent_process_name IN ("httpd","apache2","nginx","php-fpm","php-cgi","php","w3wp.exe","java","tomcat") AND Processes.process_name IN ("sh","bash","dash","id","whoami","uname","curl","wget","nc","ncat","python","python3","perl")) OR Processes.process="*suo5*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let webParents = dynamic(["httpd","apache2","nginx","php-fpm","php-cgi","php","w3wp.exe","java","tomcat"]);
let shells = dynamic(["sh","bash","dash","id","whoami","uname","curl","wget","nc","ncat","python","python3","perl"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where (InitiatingProcessFileName in~ (webParents) and FileName in~ (shells))
   or ProcessCommandLine has "suo5" or FileName has "suo5"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `43.246.208.207`, `103.97.0.57`, `118.107.222.232`, `202.181.27.115`, `redhatupdating432.dnsrd.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-3156`, `CVE-2021-4034`, `CVE-2017-7269`, `CVE-2026-43503`, `CVE-2026-31431`, `CVE-2026-43284`, `CVE-2026-43500`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0f8c905aa25c86f85454acb7e77bf5c50220c2a82e5b69a33741e55c8a85f2fc`, `a9447ae174f4aa54f760b7d7cc985c1a970f31e151d3ff66fac247f99ba1b509`, `ec7e9ab43a0cc65d29f0b84a93ba88c43d01fed3dec5c968525dc73c03cbfda2`, `b65b7ede835ebba36294d52d7780065523340ee09bb8b209ef2dc495e53dfd53`, `d252ee7b348b7e43e432d8fb154465838f5cd5fb564905323460e6f0a0c7d1e2`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
