# [HIGH] Nottingham University data breach affects over 450,000 students

**Source:** BleepingComputer
**Published:** 2026-06-11
**Article:** https://www.bleepingcomputer.com/news/security/nottingham-university-data-breach-affects-over-450-000-students/

## Threat Profile

Nottingham University data breach affects over 450,000 students 
By Sergiu Gatlan 
June 11, 2026
03:27 AM
0 
The University of Nottingham confirmed on Wednesday that a hacking group gained access to its student records system in a breach affecting both current students and alums.
Nottingham University is a public research university with 7,000 staff and over 46,000 students, ranking in the Top 20 in the United Kingdom and the Top 100 worldwide.
The university told BleepingComputer in an emailed …

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

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1059.004** — Unix Shell
- **T1082** — System Information Discovery
- **T1083** — File and Directory Discovery
- **T1505.003** — Server Software Component: Web Shell
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.004** — Remote Services: SSH
- **T1110.004** — Credential Stuffing
- **T1570** — Lateral Tool Transfer
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Local Data Staging
- **T1491.001** — Defacement: Internal Defacement
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ShinyHunters CVE-2026-35273 exploit POST to PeopleSoft /PSEMHUB/hub

`UC_41_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.src) as src_ip values(Web.status) as status from datamodel=Web where (Web.url="*/PSEMHUB/hub*" OR Web.url="*/PSEMHUB/envmetadata/*" OR Web.url="*/PSIGW/HttpListeningConnector*") Web.http_method=POST by Web.dest Web.src Web.user_agent | `drop_dm_object_name(Web)` | where status<500 OR src="142.11.200.186" OR src="142.11.200.187" OR src="142.11.200.188" OR src="142.11.200.189" OR src="142.11.200.190" OR src="108.174.202.99" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CVE-2026-35273 staging-IP touch on PeopleSoft web tier — Defender can't see HTTP path, so pivot on the published staging /29 hitting PeopleSoft hosts on 80/443.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in ("InboundConnectionAccepted","ConnectionAccepted","ConnectionSuccess")
| where LocalPort in (80,443,8000,8443,7777,7778)   // PeopleTools/WebLogic default listeners
| where RemoteIP in ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99")
| project Timestamp, DeviceName, DeviceId, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### WebLogic/Java spawning Linux recon shell after PSEMHUB exploit

`UC_41_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("java","weblogic","java.exe") AND (Processes.process="*psappsrv.cfg*" OR Processes.process="*ps_config_homes*" OR Processes.process="*WebLogic*config.xml*" OR Processes.process="*hostname*id*" OR Processes.process="*mount*psoft*" OR Processes.process_name IN ("hostname","id","whoami","uname")) by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("java","weblogic.Server","startWebLogic.sh") or InitiatingProcessParentFileName has_any ("java","weblogic.Server")
| where FileName in ("hostname","id","whoami","uname","mount","cat","grep","sh","bash")
| where ProcessCommandLine has_any ("psappsrv.cfg","ps_config_homes","/u01/app/psoft","WebLogic","config.xml","/etc/hosts","Address=","HostName=")
   or (FileName in ("hostname","id") and InitiatingProcessFileName has "java")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### JSP webshell drop under PeopleSoft PSEMHUB.war

`UC_41_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/PSEMHUB.war/*" OR Filesystem.file_path="*/peoplesoft/PSEMHUB*" OR Filesystem.file_path="*envmetadata/transactions*" OR Filesystem.file_path="*envmetadata/data/environment*") AND (Filesystem.file_name="*.jsp" OR Filesystem.file_name="*.class" OR Filesystem.file_name="*.war" OR Filesystem.file_name="*.xml") by host Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/PSEMHUB.war/","/peoplesoft/PSEMHUB","envmetadata/transactions","envmetadata/data/environment","PSEMHUB.war/persistantstorage","PSEMHUB.war/scratchpad")
| where FileName endswith ".jsp" or FileName endswith ".class" or FileName endswith ".war" or (FileName endswith ".xml" and FolderPath has "envmetadata/data/environment")
| where InitiatingProcessFileName !in~ ("oracle-installer","psadmin","pside")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### MeshCentral Azure-disguised agent + azurenetfiles.net C2 channel

`UC_41_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(`tstats` `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name IN ("meshagent64-azure-ops.exe","meshagent64-v2.exe","meshagent32-azure-ops.exe","meshagent") OR Processes.process="*azurenetfiles.net*" OR Processes.process="*agent.ashx*") OR Processes.process_hash IN ("f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc","d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f","c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f","68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309") by host Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`) | append [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query="*azurenetfiles.net" by DNS.src DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let StagingIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190"]);
let AgentHashes = dynamic(["f02a924c9ff92a8780ce812511341182c6b509d45bc59f3f7b522e37225d24fc","d83fdb9e53c5ff03c4cb0451ea1bebd79b53f29eadc1e2fa394c7af13a86ce2f","c7e9332731b06644fc73e0046a2a89eaa59b09f54250e9bd622467187351711f","68257a6f9ff196179ec03624e849927f26599eb180a7c82e14ef5bc4e93bc309"]);
let ProcHits = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName in~ ("meshagent64-azure-ops.exe","meshagent64-v2.exe","meshagent32-azure-ops.exe","meshagent")
     or SHA256 in (AgentHashes)
     or ProcessCommandLine has_any ("azurenetfiles.net","agent.ashx","meshctrl.js")
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName;
let NetHits = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "azurenetfiles.net" or RemoteIP in (StagingIPs) or RemoteUrl endswith "agent.ashx"
  | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine;
union ProcHits, NetHits
| order by Timestamp desc
```

### ShinyHunters fanout.sh SSH credential spray from PeopleSoft host

`UC_41_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.dest) as targets dc(Processes.process) as cmd_count from datamodel=Endpoint.Processes where Processes.process_name="sshpass" OR (Processes.process_name="ssh" AND Processes.process="*StrictHostKeyChecking=no*") OR Processes.process="*_fanout.sh*" by host Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | where cmd_count > 5 OR cmdline="*_fanout.sh*" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Window = 10m;
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sshpass","ssh") or ProcessCommandLine has_any ("_fanout.sh","StrictHostKeyChecking=no")
| where ProcessCommandLine has_any ("sshpass -p","StrictHostKeyChecking=no","webserv/CSPRD","appserv/prcs","_fanout.sh")
| where InitiatingProcessAccountName !in~ ("root","ansible") or ProcessCommandLine has "_fanout.sh"
| summarize FanoutTargets = dcount(ProcessCommandLine),
            Hosts = make_set(ProcessCommandLine, 50),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, AccountName, bin(Timestamp, Window)
| where FanoutTargets >= 5 or Hosts has "_fanout.sh"
| order by LastSeen desc
```

### zstd / pv archive staging of PeopleSoft exfil on application host

`UC_41_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process_name="zstd" OR Processes.process_name="tar" OR Processes.process_name="pv" OR Processes.process_name="7z") AND (Processes.process="*exfil*" OR Processes.process="*ps_config_homes*" OR Processes.process="*/u01/app/psoft*" OR Processes.process="*.tar.zst*" OR Processes.process="*-T0*" OR Processes.process="*PSEMHUB*") by host Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("zstd","tar","pv","7z","7za","7zz")
| where ProcessCommandLine has_any ("exfil",".tar.zst","/u01/app/psoft","ps_config_homes","PSEMHUB","-T0","webserv/CSPRD")
   or (FileName =~ "zstd" and ProcessCommandLine has "-T0")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### ShinyHunters defacement README drop on PeopleSoft hosts

`UC_41_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.file_name="README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT" OR Filesystem.file_name="README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED*" by host Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName =~ "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT"
   or FileName startswith "README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.200.186`, `142.11.200.187`, `142.11.200.188`, `142.11.200.189`, `142.11.200.190`, `108.174.202.99`, `176.120.22.24`, `azurenetfiles.net`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
