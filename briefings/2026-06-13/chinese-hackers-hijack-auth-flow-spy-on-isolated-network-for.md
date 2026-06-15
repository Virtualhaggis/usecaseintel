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
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1555** — Credentials from Password Stores
- **T1040** — Network Sniffing
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1090** — Proxy
- **T1133** — External Remote Services
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1573** — Encrypted Channel
- **T1219** — Remote Access Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant PAM Module Replacement (pam_unix.so backdoor)

`UC_7_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/usr/lib/*-linux-gnu/security/*") AND Filesystem.action IN ("created","modified","write","rename") AND (Filesystem.file_name="pam_unix.so" OR Filesystem.file_name="pam_*.so") AND NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","update-alternatives","authselect","pam-auth-update") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"/lib/security/", @"/lib64/security/", @"/usr/lib/x86_64-linux-gnu/security/", @"/usr/lib/aarch64-linux-gnu/security/")
| where FileName =~ "pam_unix.so" or (FileName startswith "pam_" and FileName endswith ".so")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","update-alternatives","authselect","pam-auth-update","pamtester","unattended-upgrade")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant Trojanized OpenSSH Binary Replacement (ssh/sshd/scp)

`UC_7_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/bin/ssh","/usr/sbin/sshd","/usr/bin/scp","/usr/sbin/scp","/usr/libexec/openssh/sftp-server","/usr/bin/ssh-agent") AND Filesystem.action IN ("created","modified","write","rename") AND NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","update-alternatives","unattended-upgrade") by Filesystem.dest Filesystem.file_path Filesystem.file_hash Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath in~ ("/usr/bin/ssh","/usr/sbin/sshd","/usr/bin/scp","/usr/sbin/scp","/usr/bin/ssh-agent","/usr/libexec/openssh/sftp-server")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","update-alternatives","unattended-upgrade","snapd")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### FastCGI Bridge Execution Chain: fcgiwrap → uptime → ssh (air-gap pivot)

`UC_7_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" AND Processes.process_name IN ("uptime","ssh","nc","ncat","netcat","bash","sh")) OR (Processes.parent_process_name="uptime" AND Processes.process_name IN ("ssh","scp","sshpass","nc","ncat")) OR (Processes.parent_process_name="nginx" AND Processes.process_name="fcgiwrap") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName =~ "fcgiwrap" and FileName in~ ("uptime","ssh","nc","ncat","netcat","bash","sh","sshpass"))
    or (InitiatingProcessFileName =~ "uptime" and FileName in~ ("ssh","scp","sshpass","nc","ncat","netcat"))
    or (InitiatingProcessFileName =~ "nginx" and FileName in~ ("fcgiwrap","sh","bash","ssh"))
| project Timestamp, DeviceName, AccountName,
          ParentFileName = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath,
          ChildFileName = FileName,
          ChildCmd = ProcessCommandLine,
          ChildPath = FolderPath,
          SHA256
| order by Timestamp desc
```

### smbd Process Masquerading from Non-Canonical Path (Velvet Ant SOCKS5 proxy)

`UC_7_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="smbd*-D*" OR Processes.process_name="smbd") AND NOT Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/usr/local/samba/sbin/smbd") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | where parent_process_name!="systemd" AND parent_process_name!="init" AND parent_process_name!="smbd" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "smbd" or ProcessCommandLine startswith "smbd ")
| where FolderPath !in~ ("/usr/sbin/smbd","/usr/local/sbin/smbd","/usr/local/samba/sbin/smbd","/opt/samba/sbin/smbd")
    or InitiatingProcessFileName !in~ ("systemd","init","smbd","supervisord")
| where not(FolderPath in~ ("/usr/sbin/smbd","/usr/local/sbin/smbd") and InitiatingProcessFileName in~ ("systemd","init","smbd"))
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine, SHA256, MD5,
          ParentFileName = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath
| order by Timestamp desc
```

### GS-Netcat Relay C2 (gs.thc.org) + systemd Persistence Service

`UC_7_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query="gs.thc.org" OR DNS.query="*.thc.org" OR DNS.query="*.gsocket.io" OR DNS.query="gsocket.io") by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/*.service" OR Filesystem.file_path="/usr/lib/systemd/system/*.service" OR Filesystem.file_path="/etc/rc.local" OR Filesystem.file_path="/etc/profile.d/*") AND Filesystem.action IN ("created","modified","write") AND NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","systemctl","systemd-sysv-install") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
// Branch A: DNS / network to GS-Netcat relay infrastructure
let GsNetcatC2 = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any ("gs.thc.org",".thc.org","gsocket.io")
         or RemoteUrl =~ "gs.thc.org"
    | project Timestamp, DeviceName, ActionType,
              Signal="GS-Netcat C2 connection",
              RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessAccountName;
// Branch B: systemd persistence units written by non-package-manager processes
let SystemdPersistence = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has_any (@"/etc/systemd/system/", @"/usr/lib/systemd/system/", @"/etc/rc.local", @"/etc/profile.d/")
    | where FileName endswith ".service" or FileName in~ ("rc.local","bashrc") or FolderPath has "/profile.d/"
    | where ActionType in ("FileCreated","FileModified")
    | where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","systemctl","systemd-sysv-install","unattended-upgrade","ansible-playbook")
    | project Timestamp, DeviceName, ActionType,
              Signal="systemd persistence unit write",
              RemoteUrl=tostring(""), RemoteIP=tostring(""), RemotePort=int(null),
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessAccountName;
GsNetcatC2
| union SystemdPersistence
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
