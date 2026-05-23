# [CRIT] From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5 and Confluence

**Source:** Microsoft Security Blog
**Published:** 2026-05-22
**Article:** https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/

## Threat Profile

Tags 
Credential theft 
Linux 
Content types 
Research 
Products and services 
Microsoft Defender 
Topics 
Actionable threat insights 
Detection and protection success stories 
A growing trend in modern intrusions is the compromise of internet-facing edge appliances such as firewalls and VPN gateways. Systems traditionally deployed as security boundaries are increasingly becoming initial access points due to the continued discovery and exploitation of critical vulnerabilities.
Because these devi…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-33073`
- **IPv4 (defanged):** `206.189.27.39`
- **SHA256:** `4a927d031919fd6bd88d3c8a917214b54bca00f8ddc80ecfe4d230663dda7465`
- **SHA256:** `b4592cea69699b2c0737d4e19cff7dca17b5baf5a238cd6da950a37e9986f216`
- **SHA256:** `710a9d2653c8bd3689e451778dab9daec0de4c4c75f900788ccf23ef254b122a`
- **SHA256:** `57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517`
- **SHA256:** `bdd5da81ac34d9faa2a5118d4ed8f492239734be02146cd24a0e34270a48a455`

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
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1005** — Data from Local System
- **T1187** — Forced Authentication
- **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
- **T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting
- **T1136.001** — Create Account: Local Account
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1046** — Network Service Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Linux wget/curl fetching HackTool:Linux/MalPack.B from 206.189.27.39:8888

`UC_15_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("wget","curl") OR Processes.process IN ("*wget*","*curl*")) (Processes.process="*206.189.27.39*" OR Processes.process="*206.189.27[.]39*") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wget","curl") or InitiatingProcessFileName in~ ("wget","curl")
| where ProcessCommandLine has "206.189.27.39" or InitiatingProcessCommandLine has "206.189.27.39"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Linux curl FTP fetch writing payload into /dev/shm (tmpfs staging)

`UC_15_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="curl" Processes.process="*ftp://*" Processes.process="*/dev/shm/*" by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "curl" or InitiatingProcessFileName =~ "curl"
| where ProcessCommandLine has "ftp://" and ProcessCommandLine has "/dev/shm/"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Confluence credential file access (server.xml / confluence.cfg.xml) by non-Confluence process

`UC_15_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/opt/atlassian/confluence/conf/server.xml*" OR Processes.process="*/var/atlassian/application-data/confluence/confluence.cfg.xml*") NOT Processes.parent_process_name IN ("java","tomcat","start-confluence.sh","systemd") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("/opt/atlassian/confluence/conf/server.xml","/var/atlassian/application-data/confluence/confluence.cfg.xml")
| where not (InitiatingProcessFileName in~ ("java","tomcat","start-confluence.sh","systemd","logrotate"))
| where not (FileName in~ ("java","tomcat"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] NetExec/nxc PetitPotam coerce_plus with marshalled-target SMB payload

`UC_15_12` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*coerce_plus*" OR Processes.process="*M=PetitPotam*" OR Processes.process="*localhost1UWhRC*" OR Processes.process_name IN ("nxc","netexec")) by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("coerce_plus","M=PetitPotam","localhost1UWhRC")
   or (FileName in~ ("nxc","netexec") and ProcessCommandLine has "-M ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] CVE-2025-33073 Reflective Kerberos Relay exploit script + dnstool DNS record injection

`UC_15_13` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*CVE-2025-33073*" OR (Processes.process="*dnstool.py*" AND Processes.process="*-a add*") OR (Processes.process="*dnstool.py*" AND Processes.process="*localhost1UWhRC*") OR Processes.process="*krbrelayx*") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "CVE-2025-33073"
   or (ProcessCommandLine has "dnstool.py" and ProcessCommandLine has_any ("-a add","localhost1UWhRC"))
   or ProcessCommandLine has "krbrelayx"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] gowitness HTTP/HTTPS recon scan with Chrome SOCKS5 proxy on internal subnet

`UC_15_14` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="gowitness" OR Processes.process="*gowitness*") (Processes.process="*--write-screenshots*" OR Processes.process="*--screenshot-fullpage*" OR Processes.process="*--chrome-proxy socks5://*" OR Processes.process_hash="57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517") by Processes.dest Processes.user Processes.process Processes.process_hash Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "gowitness" or InitiatingProcessFileName =~ "gowitness" or ProcessCommandLine has "gowitness scan nmap")
   or (ProcessCommandLine has_all ("--write-screenshots","--chrome-proxy","socks5://"))
   or SHA256 == "57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5

`UC_15_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5 ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("cve-2025-33073.py","dnstool.py","setenv.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/shm/ag*" OR Filesystem.file_path="*/opt/atlassian/confluence/conf/server.xml*" OR Filesystem.file_path="*/var/atlassian/application-data/confluence/confluence.cfg.xml*" OR Filesystem.file_path="*/opt/atlassian/confluence/bin/bootstrap.jar*" OR Filesystem.file_path="*/dev/shm*" OR Filesystem.file_path="*/dev/shm/*" OR Filesystem.file_name IN ("cve-2025-33073.py","dnstool.py","setenv.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — From edge appliance to enterprise compromise: Multi-stage Linux intrusion via F5
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("cve-2025-33073.py", "dnstool.py", "setenv.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/shm/ag", "/opt/atlassian/confluence/conf/server.xml", "/var/atlassian/application-data/confluence/confluence.cfg.xml", "/opt/atlassian/confluence/bin/bootstrap.jar", "/dev/shm", "/dev/shm/") or FileName in~ ("cve-2025-33073.py", "dnstool.py", "setenv.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `206.189.27.39`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-33073`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4a927d031919fd6bd88d3c8a917214b54bca00f8ddc80ecfe4d230663dda7465`, `b4592cea69699b2c0737d4e19cff7dca17b5baf5a238cd6da950a37e9986f216`, `710a9d2653c8bd3689e451778dab9daec0de4c4c75f900788ccf23ef254b122a`, `57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517`, `bdd5da81ac34d9faa2a5118d4ed8f492239734be02146cd24a0e34270a48a455`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
