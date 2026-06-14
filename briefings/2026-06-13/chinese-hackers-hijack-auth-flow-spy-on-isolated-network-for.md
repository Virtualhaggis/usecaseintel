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
- **T1554** — Compromise Host Software Binary
- **T1556** — Modify Authentication Process
- **T1056.001** — Input Capture: Keylogging
- **T1572** — Protocol Tunneling
- **T1090.001** — Internal Proxy
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### pam_unix.so binary modification in /lib/security or /lib64/security

`UC_7_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") AND (Filesystem.file_path="*/lib/security/pam_*.so" OR Filesystem.file_path="*/lib64/security/pam_*.so" OR Filesystem.file_path="*/usr/lib/security/pam_*.so" OR Filesystem.file_path="*/usr/lib64/security/pam_*.so") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | where NOT (process_name IN ("dpkg","rpm","yum","dnf","apt-get","apt","zypper","pacman")) | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/lib/security/", "/lib64/security/", "/usr/lib/security/", "/usr/lib64/security/")
| where FileName startswith "pam_" and FileName endswith ".so"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt-get", "apt", "zypper", "pacman", "rpm-installd"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH ssh/sshd/scp binary replacement on Linux endpoints

`UC_7_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") AND Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/bin/ssh-agent","/usr/bin/ssh-keygen","/usr/libexec/openssh/sftp-server") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | where NOT (process_name IN ("dpkg","rpm","yum","dnf","apt-get","apt","zypper","pacman")) | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath in~ ("/usr/sbin/", "/usr/bin/", "/usr/libexec/openssh/")
| where FileName in~ ("sshd", "ssh", "scp", "ssh-agent", "ssh-keygen", "sftp-server", "ssh-keyscan")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt-get", "apt", "zypper", "pacman"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### fcgiwrap spawning ssh/scp child for cross-segment HTTP-to-SSH bridge

`UC_7_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="fcgiwrap" AND Processes.process_name IN ("ssh","scp","sshpass","nc","ncat","socat","bash","sh","uptime") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "fcgiwrap"
   or InitiatingProcessParentFileName =~ "fcgiwrap"
| where FileName in~ ("ssh", "scp", "sshpass", "nc", "ncat", "socat", "bash", "sh", "uptime")
   or ProcessCommandLine has_any ("ssh ", "scp ", "sshpass")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          SHA256
| order by Timestamp desc
```

### smbd daemon executed from non-standard path masquerading as Samba

`UC_7_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="smbd" OR Processes.process="*smbd*-D*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where NOT (process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd")) OR NOT (parent_process_name IN ("systemd","init","smbd")) | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "smbd" or ProcessCommandLine matches regex @"(?i)\bsmbd\s+-D\b"
| where not(FolderPath in~ ("/usr/sbin/", "/usr/local/sbin/", "/opt/samba/sbin/"))
   or not(InitiatingProcessFileName in~ ("systemd", "init", "smbd"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### New or modified systemd unit ExecStart pointing outside system binary paths

`UC_7_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") AND (Filesystem.file_path="/etc/systemd/system/*.service" OR Filesystem.file_path="/usr/lib/systemd/system/*.service" OR Filesystem.file_path="/lib/systemd/system/*.service" OR Filesystem.file_path="/etc/rc.local" OR Filesystem.file_path="/etc/profile.d/*" OR Filesystem.file_path="/etc/init.d/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT (process_name IN ("dpkg","rpm","yum","dnf","apt-get","apt","zypper","pacman","systemctl","systemd-sysusers")) | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/", "/etc/init.d/", "/etc/profile.d/")
   or FileName in~ ("rc.local")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt-get", "apt", "zypper", "pacman", "systemctl", "systemd-sysusers", "systemd-tmpfiles"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
