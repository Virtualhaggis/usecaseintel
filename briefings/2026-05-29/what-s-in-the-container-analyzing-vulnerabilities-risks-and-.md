# [CRIT] What’s in the container? Analyzing vulnerabilities, risks and protection with Kaspersky Container Security and the KIRA AI assistant

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-29
**Article:** https://securelist.com/container-security-typical-issues/119974/

## Threat Profile

Table of Contents
Introduction 
Software vulnerabilities and compromise of update sources 
Configuration vulnerabilities 
Insecure handling of credentials 
Use of default passwords 
Passing passwords via command arguments 
Privilege escalation in the container 
Attacks on sudo 
Insecure file permissions 
Lack of integrity checks 
Conclusion 
Authors
Yaroslav Shmelev 
Anton Kivva 
Denis Parinov 
Vladimir Kuskov 
Yanina Balandyuk-Opalinskaya 
Introduction 
Containerization using Docker has become …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2023-4911`
- **CVE:** `CVE-2021-4034`
- **CVE:** `CVE-2025-49844`
- **CVE:** `CVE-2026-24061`
- **CVE:** `CVE-2025-32463`
- **CVE:** `CVE-2017-9841`
- **CVE:** `CVE-2023-33246`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1203** — Exploitation for Client Execution
- **T1059.004** — Unix Shell
- **T1068** — Exploitation for Privilege Escalation
- **T1548.003** — Sudo and Sudo Caching
- **T1014** — Rootkit
- **T1574.006** — Dynamic Linker Hijacking
- **T1552.001** — Credentials in Files
- **T1552.003** — Bash History
- **T1078.001** — Default Accounts
- **T1046** — Network Service Discovery
- **T1018** — Remote System Discovery
- **T1071.001** — Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1496** — Resource Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Web service in container spawning interactive shell (Redis/nginx RCE)

`UC_265_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("redis-server","nginx","node","java","httpd","apache2") Processes.process_name IN ("sh","bash","dash","busybox","ash") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | where match(process, "(?i)(curl|wget|chmod|/tmp/|/dev/shm/|base64|nc |bash -i)") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("redis-server","nginx","node","java","httpd","apache2","php-fpm")
| where FileName in~ ("sh","bash","dash","busybox","ash","zsh")
| where ProcessCommandLine has_any ("curl ","wget ","/tmp/","/dev/shm/","chmod +x","base64 -d","bash -i","|sh","|bash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Container privilege escalation via Looney Tunables, PwnKit, sudo chroot

`UC_265_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process IN ("*GLIBC_TUNABLES=glibc.*","*pkexec*","*sudo --chroot*","*sudo -R *") OR Processes.process_name="pkexec") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine has "GLIBC_TUNABLES=glibc.")
    or (FileName =~ "pkexec" and InitiatingProcessAccountName != "root")
    or (FileName =~ "sudo" and ProcessCommandLine has_any ("--chroot "," -R /","--chroot="," -R="))
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### perfctl rootkit — /etc/ld.so.preload write or LD_PRELOAD on root daemon

`UC_265_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="/etc/ld.so.preload" Filesystem.action IN ("created","modified","written") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
(
  DeviceFileEvents
  | where Timestamp > ago(7d)
  | where FolderPath =~ "/etc/ld.so.preload" or FileName =~ "ld.so.preload"
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
),
(
  DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where ProcessCommandLine has "LD_PRELOAD="
  | where not (ProcessCommandLine has_any ("LD_PRELOAD=/usr/lib/","LD_PRELOAD=/lib/x86_64-linux-gnu/"))
  | project Timestamp, DeviceName, ActionType="LD_PRELOAD_exec", FolderPath, FileName, InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessAccountName=AccountName
)
| order by Timestamp desc
```

### Container default credential leak — PKP_DB_PASSWORD=changeMePlease and --secret

`UC_265_7` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process IN ("*PKP_DB_PASSWORD=*","*=changeMePlease*","* --secret *","*MYSQL_ROOT_PASSWORD=*","*POSTGRES_PASSWORD=postgres*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("PKP_DB_PASSWORD=","=changeMePlease"," --secret ","MYSQL_ROOT_PASSWORD=","POSTGRES_PASSWORD=postgres","REDIS_PASSWORD=redis")
| where not (InitiatingProcessFileName in~ ("vault","sops","kubectl"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Container-to-container horizontal scan — Dero miner self-propagation

`UC_265_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.dest) as unique_dests min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (22,2375,2376,6379,8080,9000,9200,2379,5432,3306) by All_Traffic.src All_Traffic.dest_port _time span=5m | `drop_dm_object_name(All_Traffic)` | where unique_dests > 50 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionAttempt" or ActionType == "ConnectionSuccess"
| where RemotePort in (22, 2375, 2376, 6379, 8080, 9000, 9200, 2379, 5432, 3306)
| where RemoteIPType in ("Private","Public")
| summarize UniqueDests = dcount(RemoteIP), Ports = make_set(RemotePort, 10), SampleCmd = any(InitiatingProcessCommandLine)
          by DeviceName, LocalIP, InitiatingProcessFileName, bin(Timestamp, 5m)
| where UniqueDests > 50
| order by UniqueDests desc
```

### Container egress to cryptominer pool / Kinsing C2

`UC_265_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (3333,4444,5555,7777,14444,14433,45700) OR All_Traffic.app IN ("xmrig","kinsing","perfctl") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
(
  DeviceNetworkEvents
  | where Timestamp > ago(1d)
  | where RemotePort in (3333, 4444, 5555, 7777, 14444, 14433, 45700)
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Signal="stratum_port"
),
(
  DeviceNetworkEvents
  | where Timestamp > ago(1d)
  | where RemoteUrl has_any ("xmrig","kinsing","perfctl","derohe.org","dero-stratum","minexmr","supportxmr","nanopool","pool.minexmr")
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Signal="miner_url"
)
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

### Article-specific behavioural hunt — What’s in the container? Analyzing vulnerabilities, risks and protection with Ka

`UC_265_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — What’s in the container? Analyzing vulnerabilities, risks and protection with Ka ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/apache2/apache2.conf*" OR Filesystem.file_path="*/var/www*" OR Filesystem.file_path="*/etc/apache2/conf-enabled/pkp.conf*" OR Filesystem.file_path="*/usr/local/bin/pkp-start*" OR Filesystem.file_path="*/etc/sudoers.d/solr*" OR Filesystem.file_path="*/etc/sudoers*" OR Filesystem.file_path="*/usr/share/cargo*" OR Filesystem.file_path="*/usr/share/cargo/bin*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — What’s in the container? Analyzing vulnerabilities, risks and protection with Ka
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/apache2/apache2.conf", "/var/www", "/etc/apache2/conf-enabled/pkp.conf", "/usr/local/bin/pkp-start", "/etc/sudoers.d/solr", "/etc/sudoers", "/usr/share/cargo", "/usr/share/cargo/bin"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`, `CVE-2023-4911`, `CVE-2021-4034`, `CVE-2025-49844`, `CVE-2026-24061`, `CVE-2025-32463`, `CVE-2017-9841`, `CVE-2023-33246`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
