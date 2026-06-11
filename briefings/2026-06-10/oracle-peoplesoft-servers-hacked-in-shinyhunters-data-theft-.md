# [HIGH] Oracle PeopleSoft servers hacked in ShinyHunters data theft attacks

**Source:** BleepingComputer
**Published:** 2026-06-10
**Article:** https://www.bleepingcomputer.com/news/security/oracle-peoplesoft-servers-hacked-in-shinyhunters-data-theft-attacks/

## Threat Profile

Oracle PeopleSoft servers hacked in ShinyHunters data theft attacks 
By Lawrence Abrams 
June 10, 2026
02:31 PM
0 
Oracle PeopleSoft servers are being targeted in ongoing data theft attacks by the ShinyHunters extortion gang, which claims to have stolen data from over 100 organizations.
PeopleSoft is an enterprise business software suite used by large organizations to manage business operations such as human resources, payroll, finance, supply chain management, procurement, and student administr…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.11.200.186`
- **IPv4 (defanged):** `142.11.200.187`
- **IPv4 (defanged):** `142.11.200.188`
- **IPv4 (defanged):** `142.11.200.189`
- **IPv4 (defanged):** `142.11.200.190`
- **IPv4 (defanged):** `108.174.202.99`
- **IPv4 (defanged):** `176.120.22.24`
- **Domain (defanged):** `azurenetfiles.net`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts
- **T1657** — Financial Theft
- **T1565.001** — Stored Data Manipulation
- **T1110.003** — Password Spraying
- **T1078.003** — Local Accounts
- **T1021.004** — SSH
- **T1219** — Remote Access Software
- **T1543.002** — Systemd Service
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1573** — Encrypted Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Network communication with ShinyHunters PeopleSoft attack infrastructure IPs

`UC_18_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as app values(All_Traffic.action) as action from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest in ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") OR All_Traffic.src in ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port host index sourcetype | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (badIPs) or LocalIP in (badIPs)
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, RemoteUrl
| order by Timestamp desc
```

### ShinyHunters PeopleSoft ransom-note file write (README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT)

`UC_18_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_name="README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT" OR Filesystem.file_path="*README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT") by Filesystem.dest Filesystem.user Filesystem.file_name host | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName =~ "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT"
   or FolderPath has "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### SSH credential spray against PeopleSoft administrative accounts (psoft, oracle, linuxadm)

`UC_18_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Authentication.action) as actions values(Authentication.dest) as dest_hosts dc(Authentication.dest) as host_count dc(Authentication.user) as user_count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.app="sshd" AND Authentication.user IN ("psoft","oracle","linuxadm") by Authentication.src Authentication.user | `drop_dm_object_name(Authentication)` | where host_count>=2 OR (user_count>=2) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where Protocol =~ "Ssh" or InitiatingProcessFileName in~ ("sshd","sshd-session")
| where AccountName in~ ("psoft","oracle","linuxadm")
| summarize Attempts = count(),
            Successes = countif(ActionType =~ "LogonSuccess"),
            Failures = countif(ActionType =~ "LogonFailed"),
            TargetHosts = dcount(DeviceName),
            HostList = make_set(DeviceName, 25),
            UserList = make_set(AccountName, 10),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by RemoteIP
| where TargetHosts >= 2 or (Failures >= 5 and Successes >= 1)
| order by LastSeen desc
```

### MeshCentral agent installation on Oracle PeopleSoft Linux servers

`UC_18_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents values(Processes.user) as users from datamodel=Endpoint.Processes where (Processes.process_name IN ("meshagent","MeshAgent","MeshService","meshcmd") OR Processes.process IN ("*meshagent*","*MeshCentral*","*meshcentral.com*","*meshcentral2*") OR Processes.process="*--meshServiceName*") by Processes.dest Processes.process_name host | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MeshIndicators = dynamic(["meshagent","meshservice","meshcmd","meshcentral","meshcentral.com","meshcentral2"]);
union
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where FileName in~ ("meshagent","meshagent.exe","meshservice","meshservice.exe","meshcmd","meshcmd.exe")
        or ProcessCommandLine has_any (MeshIndicators)
        or InitiatingProcessCommandLine has_any (MeshIndicators)
   | project Timestamp, EventType = "Process", DeviceName, AccountName,
             Image = FolderPath, Cmd = ProcessCommandLine,
             ParentImage = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine, SHA256),
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where FileName in~ ("meshagent","meshagent.exe","meshservice","meshservice.exe","meshcmd")
        or FolderPath has_any ("/usr/local/mesh","/opt/meshcentral","meshagent","MeshCentral")
   | project Timestamp, EventType = "File", DeviceName, AccountName = InitiatingProcessAccountName,
             Image = FolderPath, Cmd = InitiatingProcessCommandLine,
             ParentImage = InitiatingProcessParentFileName, ParentCmd = "", SHA256)
| order by Timestamp desc
```

### DNS lookup or TLS SNI for ShinyHunters azurenetfiles.net infrastructure

`UC_18_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src_hosts values(DNS.answer) as answers from datamodel=Network_Resolution.DNS where (DNS.query="azurenetfiles.net" OR DNS.query="*.azurenetfiles.net") by DNS.src DNS.query host | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "azurenetfiles.net" or RemoteUrl endswith ".azurenetfiles.net"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
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

### Article-specific behavioural hunt — Oracle PeopleSoft servers hacked in ShinyHunters data theft attacks

`UC_18_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Oracle PeopleSoft servers hacked in ShinyHunters data theft attacks ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/hosts*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Oracle PeopleSoft servers hacked in ShinyHunters data theft attacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/hosts"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.200.186`, `142.11.200.187`, `142.11.200.188`, `142.11.200.189`, `142.11.200.190`, `108.174.202.99`, `176.120.22.24`, `azurenetfiles.net`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
