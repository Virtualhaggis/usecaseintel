# [CRIT] Chinese hackers hijack auth flow, spy on isolated network for a decade

**Source:** BleepingComputer
**Published:** 2026-06-13
**Article:** https://www.bleepingcomputer.com/news/security/chinese-hackers-hijack-auth-flow-spy-on-isolated-network-for-a-decade/

## Threat Profile

Chinese hackers hijack auth flow, spy on isolated network for a decade 
By Bill Toulas 
June 13, 2026
10:06 AM
0 
Chinese hackers took control of a target organization's authentication stack and maintained persistence for 10 years, with full visibility into the administrative activity.
Dubbed "Operation Highland," the intrusion is attributed to the Velvet Ant cyberespionage threat group, which targeted vulnerable internet-facing systems before pivoting to a network with no direct external path.
…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-20399`
- **Domain (defanged):** `gs.thc.org`

## MITRE ATT&CK Techniques

- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1219** — Remote Access Software
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1554** — Compromise Host Software Binary
- **T1040** — Network Sniffing
- **T1056.001** — Input Capture: Keylogging
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Internal Proxy
- **T1572** — Protocol Tunneling
- **T1090.003** — Multi-hop Proxy
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GS-Netcat reverse shell C2 to thc.org relay (Velvet Ant Operation Highland)

`UC_7_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="thc.org" OR DNS.query="*.thc.org" OR DNS.query="gs.thc.org") by DNS.src DNS.query DNS.answer host
| `drop_dm_object_name(DNS)`
| append [| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="gs.thc.org" OR All_Traffic.dest_host="*.thc.org") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port host | `drop_dm_object_name(All_Traffic)`]
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
// Velvet Ant GS-Netcat relay C2 — hits on Linux endpoints with MDE
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "thc.org" or RemoteUrl =~ "gs.thc.org"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessSHA256
| order by Timestamp desc
```

### PAM module replacement in /lib*/security (Velvet Ant backdoored pam_unix.so)

`UC_7_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/pam_*.so" OR Filesystem.file_path="/lib64/security/pam_*.so" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/pam_*.so" OR Filesystem.file_path="/usr/lib/x86_64-linux-gnu/security/pam_*.so" OR Filesystem.file_path="/usr/lib64/security/pam_*.so") AND Filesystem.action IN ("created","modified","renamed") AND NOT (Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","pacman","unattended-upgrade","update-alternatives","snapd")) by host Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name Filesystem.process Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
// Velvet Ant pam_unix.so backdoor drop — sensor must be MDE for Linux
let pkg_managers = dynamic(["dpkg","apt","apt-get","yum","dnf","rpm","zypper","pacman","unattended-upgrade","update-alternatives","snapd","snap"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/lib/security/", "/lib64/security/", "/lib/x86_64-linux-gnu/security/", "/usr/lib/x86_64-linux-gnu/security/", "/usr/lib64/security/")
| where FileName endswith ".so" and FileName startswith "pam_"
| where InitiatingProcessFileName !in~ (pkg_managers)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binary replacement (ssh/sshd/scp) outside package manager (Velvet Ant trojanized SSH)

`UC_7_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/sbin/ssh","/usr/bin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/local/sbin/sshd","/usr/local/bin/ssh","/usr/local/bin/scp","/bin/ssh","/sbin/sshd")) AND Filesystem.action IN ("created","modified","renamed","deleted") AND NOT (Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","pacman","unattended-upgrade","update-alternatives","snapd")) by host Filesystem.file_path Filesystem.action Filesystem.process_name Filesystem.process Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
// Velvet Ant trojanized ssh/sshd/scp swap
let pkg_managers = dynamic(["dpkg","apt","apt-get","yum","dnf","rpm","zypper","pacman","unattended-upgrade","update-alternatives","snapd","snap"]);
let ssh_binaries = dynamic(["ssh","sshd","scp","ssh-agent","ssh-keysign"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/usr/sbin/","/usr/bin/","/bin/","/sbin/","/usr/local/sbin/","/usr/local/bin/")
| where FileName in~ (ssh_binaries)
| where InitiatingProcessFileName !in~ (pkg_managers)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileSize,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### smbd process masquerading as Samba daemon (Velvet Ant SOCKS5 proxy)

`UC_7_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="smbd" OR Processes.process="smbd -D*" OR Processes.process="*/smbd -D*") by host Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process Processes.parent_process_path Processes.dest
| `drop_dm_object_name(Processes)`
| eval canonical_path = if(match(process_path, "^(/usr/sbin|/usr/local/sbin|/opt/samba/sbin)/smbd$"), 1, 0)
| eval canonical_parent = if(match(parent_process_name, "^(systemd|init|samba|smbd)$"), 1, 0)
| where canonical_path=0 OR canonical_parent=0
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
// Velvet Ant SOCKS5 proxy masquerading as smbd -D
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "smbd" or ProcessCommandLine matches regex @"(^|[\s/])smbd\s+(-D|--daemon)\b"
| where (FolderPath !startswith "/usr/sbin/" and FolderPath !startswith "/usr/local/sbin/" and FolderPath !startswith "/opt/samba/")
    or InitiatingProcessFileName !in~ ("systemd","init","samba","smbd")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### fcgiwrap spawning ssh or 'uptime' binary (Velvet Ant air-gap pivot bridge)

`UC_7_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process_name="php-fpm") AND (Processes.process_name IN ("ssh","scp","nc","ncat","socat","bash","sh","dash","uptime","python","python3","perl")) by host Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| where NOT (process_name="uptime" AND process_path="/usr/bin/uptime")
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
// Velvet Ant nginx → fcgiwrap → ssh/uptime air-gap bridge
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("fcgiwrap","php-fpm","php-cgi")
| where FileName in~ ("ssh","scp","nc","ncat","socat","bash","sh","dash","uptime","python","python3","perl")
    or FolderPath has_any ("/tmp/","/var/tmp/","/dev/shm/","/var/www/")
| where not (FileName =~ "uptime" and FolderPath in~ ("/usr/bin/","/bin/"))
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessParentId
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-20399`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `gs.thc.org`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
