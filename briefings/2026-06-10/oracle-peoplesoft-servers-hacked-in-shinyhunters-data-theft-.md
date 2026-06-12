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
- **T1021.004** — Remote Services: SSH
- **T1110.003** — Brute Force: Password Spraying
- **T1078.003** — Valid Accounts: Local Accounts
- **T1485** — Data Destruction
- **T1491.001** — Defacement: Internal Defacement
- **T1657** — Financial Theft
- **T1018** — Remote System Discovery
- **T1087.001** — Account Discovery: Local Account
- **T1219** — Remote Access Software
- **T1105** — Ingress Tool Transfer
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ShinyHunters PeopleSoft attacker IPs — inbound SSH/HTTPS connections

`UC_42_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_ip IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") (All_Traffic.dest_port=22 OR All_Traffic.dest_port=8000 OR All_Traffic.dest_port=8443 OR All_Traffic.dest_port=443 OR All_Traffic.dest_port=7777) by All_Traffic.dest All_Traffic.src_ip | `drop_dm_object_name(All_Traffic)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let IOC = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IOC)
| where LocalPort in (22, 8000, 8443, 443, 7777)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SSH credential spray to PeopleSoft accounts (psoft / oracle / linuxadm)

`UC_42_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count(eval('Authentication.action'="failure")) as failures count(eval('Authentication.action'="success")) as successes values(Authentication.src) as src values(Authentication.dest) as dest from datamodel=Authentication.Authentication where Authentication.user IN ("psoft","oracle","linuxadm") Authentication.app="sshd" by Authentication.user Authentication.src _time span=10m | `drop_dm_object_name(Authentication)` | where failures >= 5 AND successes >= 1 | sort - _time
```

**Defender KQL:**
```kql
let TargetAccounts = dynamic(["psoft","oracle","linuxadm"]);
let Failures =
    DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonFailed"
    | where AccountName in~ (TargetAccounts)
    | where Protocol == "Ssh" or InitiatingProcessFileName =~ "sshd"
    | summarize FailCount = count(), FirstFail = min(Timestamp), LastFail = max(Timestamp), SourceIPs = make_set(RemoteIP, 20) by DeviceName, AccountName, bin(Timestamp, 10m)
    | where FailCount >= 5;
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where AccountName in~ (TargetAccounts)
| where Protocol == "Ssh" or InitiatingProcessFileName =~ "sshd"
| join kind=inner Failures on DeviceName, AccountName
| where Timestamp between (FirstFail .. LastFail + 5m)
| project Timestamp, DeviceName, AccountName, RemoteIP, FailCount, SourceIPs, LogonType
| order by Timestamp desc
```

### ShinyHunters ransom note file creation in PeopleSoft directories

`UC_42_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Filesystem.process_name) as process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name="README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT" OR Filesystem.file_name="README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.txt" OR Filesystem.file_path="*README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED*") Filesystem.action=created by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let PSPaths = dynamic(["/opt/oracle","/u01/app","/opt/psoft","/PS_HOME","/PS_APP_HOME","/PS_CFG_HOME","/weblogic","/tuxedo","\\PS_HOME\\","\\PT8"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FileName matches regex @"(?i)README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED\.(txt|md|html?)"
| extend InPeopleSoftPath = iff(FolderPath has_any (PSPaths), true, false)
| project Timestamp, DeviceName, FolderPath, FileName, InPeopleSoftPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### /etc/hosts enumeration followed by SSH lateral movement on PeopleSoft host

`UC_42_9` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name="cat" OR Processes.process_name="grep" OR Processes.process_name="awk" OR Processes.process_name="cut" OR Processes.process_name="sed") (Processes.process="*\/etc\/hosts*") by Processes.dest Processes.user Processes.parent_process_name _time span=5m | `drop_dm_object_name(Processes)` | rename count as hosts_reads | join type=inner dest user [| tstats summariesonly=true count as ssh_targets dc(Processes.process) as cmd_count from datamodel=Endpoint.Processes where Processes.process_name="ssh" by Processes.dest Processes.user _time span=5m | `drop_dm_object_name(Processes)` | where ssh_targets >= 3] | where hosts_reads >= 1 AND ssh_targets >= 3
```

**Defender KQL:**
```kql
let Window = 5m;
let HostsReads =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "/etc/hosts"
    | where FileName in~ ("cat","grep","awk","cut","sed","sort","head","tail")
    | project HostsReadTime = Timestamp, DeviceId, DeviceName, AccountName, HostsReader = ProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "ssh" or ProcessCommandLine matches regex @"(?i)\bssh\s+[\w\.\-]+@"
| join kind=inner HostsReads on DeviceId
| where Timestamp between (HostsReadTime .. HostsReadTime + Window)
| summarize SshTargets = dcount(ProcessCommandLine), Targets = make_set(ProcessCommandLine, 10), FirstSsh = min(Timestamp) by DeviceName, AccountName, HostsReadTime, HostsReader
| where SshTargets >= 3
| order by HostsReadTime desc
```

### MeshCentral agent deployment on PeopleSoft hosts (ShinyHunters staging)

`UC_42_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="meshagent" OR Processes.process_name="meshcentral-agent" OR Processes.process="*meshagent*" OR Processes.process="*meshcentral*" OR Processes.process="*MeshCentralRouter*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let IOC = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
let MeshExec =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName matches regex @"(?i)^mesh(agent|central[-_]?agent|centralrouter)"
        or ProcessCommandLine matches regex @"(?i)\bmesh(agent|central[-_]?agent)\b"
        or InitiatingProcessCommandLine matches regex @"(?i)\b(curl|wget)\b.*meshagent"
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
let MeshDownload =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName matches regex @"(?i)^mesh(agent|central)"
        or FileOriginUrl matches regex @"(?i)mesh(agent|central)"
        or FileOriginIP in (IOC)
    | project Timestamp, DeviceName, FileName, FolderPath, FileOriginUrl, FileOriginIP, InitiatingProcessCommandLine;
union MeshExec, MeshDownload
| order by Timestamp desc
```

### TLS connections to azurenetfiles.net or matching SAN/CN (ShinyHunters infra)

`UC_42_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query="*azurenetfiles.net*" by DNS.query | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.src) as src from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_url="*azurenetfiles.net*" OR All_Traffic.ssl_subject="*azurenetfiles.net*" OR All_Traffic.ssl_issuer_common_name="*azurenetfiles.net*") by All_Traffic.dest All_Traffic.ssl_subject] | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "azurenetfiles.net" or RemoteUrl endswith "azurenetfiles.net"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
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

`UC_42_5` · phase: **install** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
