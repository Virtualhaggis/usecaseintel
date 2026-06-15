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
- **T1095** — Non-Application Layer Protocol
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Internal Proxy
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1090.003** — Multi-hop Proxy
- **T1059.004** — Unix Shell
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1040** — Network Sniffing
- **T1543.002** — Create or Modify System Process: Systemd Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GS-Netcat reverse shell beaconing to gs.thc.org relay

`UC_16_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution where DNS.query="gs.thc.org" OR DNS.query="*.gs.thc.org" by DNS.src DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".gs.thc.org"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### SOCKS5 proxy daemon masquerading as 'smbd -D'

`UC_16_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as path values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="smbd" Processes.process="*smbd -D*" NOT (Processes.parent_process_name IN ("systemd","init","smbd","samba")) NOT (Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd")) by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "smbd" and ProcessCommandLine has "-D"
| where not (FolderPath in~ ("/usr/sbin/smbd", "/usr/local/sbin/smbd", "/opt/samba/sbin/smbd"))
| where not (InitiatingProcessFileName in~ ("systemd", "init", "smbd", "samba"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Nginx FastCGI bridge spawning 'uptime' SSH-pivot to air-gapped network

`UC_16_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as path values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process_name="nginx") AND (Processes.process_name="uptime" OR Processes.process_name="ssh") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | search (parent="fcgiwrap" AND (process_name="uptime" OR process_name="ssh")) OR (parent="nginx" AND process_name="uptime") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName =~ "fcgiwrap" and FileName in~ ("uptime", "ssh", "scp", "sh", "bash"))
   or (InitiatingProcessFileName =~ "nginx" and FileName =~ "uptime")
   or (InitiatingProcessFileName =~ "uptime" and FileName in~ ("ssh", "scp"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### PAM module replacement — pam_unix.so/pam_sshd backdoor write

`UC_16_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file values(Filesystem.process_name) as proc values(Filesystem.file_hash) as hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/usr/lib/x86_64-linux-gnu/security/*" OR Filesystem.file_path="/usr/lib64/security/*") (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="written") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","cfengine-execd","puppet","chef-client","ansible")) by host Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PamPaths = dynamic(["/lib/security/", "/lib64/security/", "/usr/lib/x86_64-linux-gnu/security/", "/usr/lib64/security/"]);
let PkgMgrs = dynamic(["dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "pacman"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (PamPaths) or FileName endswith "pam_unix.so" or FileName endswith "pam_sshd.so" or FileName matches regex @"pam_[a-z_]+\.so$"
| where not (InitiatingProcessFileName in~ (PkgMgrs))
| where not (InitiatingProcessFolderPath has_any ("/usr/lib/apt/", "/usr/lib/dpkg/", "/var/lib/dpkg/", "/var/lib/rpm/"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binary trojanisation — ssh/sshd/scp replaced outside package manager

`UC_16_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as proc values(Filesystem.file_hash) as hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/bin/ssh","/usr/sbin/sshd","/usr/bin/scp","/usr/bin/ssh-agent","/usr/bin/ssh-keygen")) (Filesystem.action="created" OR Filesystem.action="modified" OR Filesystem.action="written" OR Filesystem.action="renamed") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgr","systemd-update-helper")) by host Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SshBinaries = dynamic(["/usr/bin/ssh", "/usr/sbin/sshd", "/usr/bin/scp", "/usr/bin/ssh-agent", "/usr/bin/ssh-keygen", "/usr/bin/ssh-add"]);
let PkgMgrs = dynamic(["dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "pacman", "unattended-upgr"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where strcat(FolderPath, FileName) in~ (SshBinaries) or FolderPath endswith "/usr/bin/" and FileName in~ ("ssh", "scp", "ssh-agent") or FolderPath endswith "/usr/sbin/" and FileName =~ "sshd"
| where not (InitiatingProcessFileName in~ (PkgMgrs))
| where not (InitiatingProcessFolderPath has_any ("/usr/lib/apt/", "/usr/lib/dpkg/", "/var/lib/dpkg/", "/var/lib/rpm/"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Systemd service unit with ExecStart pointing to non-package binary (GS-Netcat persistence)

`UC_16_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.file_hash) as hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/*.service" OR Filesystem.file_path="/usr/lib/systemd/system/*.service" OR Filesystem.file_path="/lib/systemd/system/*.service") (Filesystem.action="created" OR Filesystem.action="modified") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","systemctl","systemd")) by host Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (FolderPath has_any ("/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/")) and FileName endswith ".service"
| where not (InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "systemctl"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
