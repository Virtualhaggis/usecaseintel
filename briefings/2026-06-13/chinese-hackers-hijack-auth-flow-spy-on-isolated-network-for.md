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
- **T1090.002** — Proxy: External Proxy
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1554** — Compromise Host Software Binary
- **T1555** — Credentials from Password Stores
- **T1056.001** — Input Capture: Keylogging
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090** — Proxy
- **T1090.001** — Proxy: Internal Proxy
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1037** — Boot or Logon Initialization Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GS-Netcat reverse shell beaconing to GSRN relay (gs.thc.org)

`UC_1_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.src_user) as user values(DNS.answer) as resolved_ip from datamodel=Network_Resolution where DNS.query IN ("gs.thc.org","*.gs.thc.org","*.gsrn.net") by DNS.query DNS.dest DNS.message_type | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents
   | where Timestamp > ago(30d)
   | where RemoteUrl has_any ("gs.thc.org","gsrn.net")
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName),
  (DeviceEvents
   | where Timestamp > ago(30d)
   | where ActionType == "DnsConnectionInspected"
   | extend QueryName = tostring(parse_json(AdditionalFields).query)
   | where QueryName has_any ("gs.thc.org","gsrn.net")
   | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, QueryName, RemoteIP, RemotePort, InitiatingProcessAccountName=AccountName)
| order by Timestamp desc
```

### Velvet Ant pam_unix.so backdoored module replacement

`UC_1_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/lib/security/pam_*.so","/lib64/security/pam_*.so","/lib/x86_64-linux-gnu/security/pam_*.so","/usr/lib64/security/pam_*.so","/usr/lib/x86_64-linux-gnu/security/pam_*.so") Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade","pacman") by Filesystem.dest Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"^/(usr/)?lib(64)?(/[^/]+)?/security/"
| where FileName endswith ".so"
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade","pacman","systemd","update-alternatives")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, PreviousFileName, PreviousFolderPath
| order by Timestamp desc
```

### Trojanized OpenSSH binary replacement (ssh/sshd/scp)

`UC_1_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/sbin/sshd","/usr/bin/ssh-agent","/usr/bin/ssh-keysign","/usr/libexec/openssh/*") Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade") by Filesystem.dest Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/sbin/sshd","/usr/bin/ssh-agent","/usr/bin/ssh-keysign")
      or (FolderPath startswith "/usr/libexec/openssh/")
      or (FolderPath startswith "/etc/ssh/" and FileName == "sshd_config")
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade","update-alternatives")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, PreviousFileName
| order by Timestamp desc
```

### fcgiwrap spawning ssh/scp/nc — air-gap pivot via Nginx FastCGI bridge

`UC_1_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.parent_process_name="fcgiwrap" AND Processes.process_name IN ("ssh","scp","sftp","nc","ncat","socat","bash","sh","dash","python","python3","perl","uptime") by Processes.dest Processes.user Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "fcgiwrap"
      or InitiatingProcessParentFileName =~ "fcgiwrap"
| where FileName in~ ("ssh","scp","sftp","nc","ncat","socat","bash","sh","dash","python","python3","perl","uptime")
| project Timestamp, DeviceName, AccountName,
          ParentImage=InitiatingProcessFolderPath,
          ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath,
          ChildCmd=ProcessCommandLine,
          SHA256, InitiatingProcessAccountName
| order by Timestamp desc
```

### smbd process masquerading from non-standard path or non-services parent

`UC_1_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.parent_process_name) as parent_name values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where Processes.process_name="smbd" by Processes.dest Processes.process_path Processes.parent_process_name Processes.user Processes.process | `drop_dm_object_name(Processes)` | search (process_path!="/usr/sbin/smbd" OR parent_name!="systemd") | search process="*-D*" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "smbd" or ProcessCommandLine matches regex @"(^|/)smbd(\s+|$)"
| where (FolderPath != "/usr/sbin/smbd")
      or (InitiatingProcessFileName !in~ ("systemd","init","smbd"))
      or (AccountName !in~ ("root")) 
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### New systemd unit / startup script ExecStart pointing at non-system binary

`UC_1_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/etc/systemd/system/*.service","/usr/lib/systemd/system/*.service","/etc/rc.local","/etc/profile.d/*","/root/.bashrc","/root/.bash_profile") OR Filesystem.file_path="/etc/cron.d/*") Filesystem.action IN ("created","modified") NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade","systemctl","update-alternatives","snapd","flatpak") by Filesystem.dest Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath startswith "/etc/systemd/system/" and FileName endswith ".service")
      or (FolderPath startswith "/usr/lib/systemd/system/" and FileName endswith ".service")
      or FolderPath in~ ("/etc/rc.local","/root/.bashrc","/root/.bash_profile","/root/.profile")
      or FolderPath startswith "/etc/profile.d/"
      or FolderPath startswith "/etc/cron.d/"
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade","systemctl","update-alternatives","snapd","flatpak","cloud-init")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
