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
- **T1027** — Obfuscated Files or Information
- **T1556** — Modify Authentication Process
- **T1040** — Network Sniffing
- **T1555** — Credentials from Password Stores
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Internal Proxy
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.002** — Proxy: External Proxy
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Backdoored pam_unix.so or PAM module replacement in /lib*/security/

`UC_1_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action in ("created","modified","renamed") (Filesystem.file_path="/lib/security/pam_unix.so" OR Filesystem.file_path="/lib64/security/pam_unix.so" OR Filesystem.file_path="/usr/lib/security/pam_unix.so" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/pam_unix.so" OR Filesystem.file_path="/lib/security/pam_unix2.so" OR Filesystem.file_path="/lib64/security/pam_unix2.so") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/lib/security/","/lib64/security/","/usr/lib/security/","/lib/x86_64-linux-gnu/security/")
| where FileName in~ ("pam_unix.so","pam_unix2.so","pam_sss.so","pam_ldap.so","pam_krb5.so","pam_winbind.so")
| where not (InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd","snapd"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### OpenSSH binary replacement — trojanized ssh / sshd / scp under /usr/bin or /usr/sbin

`UC_1_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action in ("created","modified","renamed") (Filesystem.file_path="/usr/sbin/sshd" OR Filesystem.file_path="/usr/bin/ssh" OR Filesystem.file_path="/usr/bin/scp" OR Filesystem.file_path="/usr/bin/ssh-keysign" OR Filesystem.file_path="/usr/libexec/openssh/sftp-server") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/usr/sbin/","/usr/bin/","/usr/libexec/openssh/","/usr/local/sbin/","/usr/local/bin/")
| where FileName in~ ("sshd","ssh","scp","sftp","sftp-server","ssh-keysign","ssh-agent")
| where not (InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","unattended-upgrade","packagekitd","snapd"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### fcgiwrap spawns ssh/nc to internal network — HTTP-to-air-gap execution bridge

`UC_1_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process_name="nginx") (Processes.process_name="ssh" OR Processes.process_name="scp" OR Processes.process_name="nc" OR Processes.process_name="ncat" OR Processes.process_name="socat" OR Processes.process_name="sshpass" OR Processes.process_name="uptime") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("fcgiwrap","nginx","php-fpm")
| where FileName in~ ("ssh","scp","sftp","nc","ncat","socat","sshpass","uptime","bash","sh")
| where ProcessCommandLine has_any ("ssh ","scp ","sshpass","-p ","-i /","-o StrictHostKeyChecking","-W ","-D ","-L ")
  or FileName =~ "uptime"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### SOCKS5 proxy daemon masquerading as 'smbd -D' from non-smbd parent

`UC_1_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="smbd" Processes.process="*smbd -D*" NOT (Processes.process_path="/usr/sbin/smbd" OR Processes.process_path="/usr/local/samba/sbin/smbd") by Processes.dest Processes.user Processes.process_path Processes.parent_process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "smbd" or ProcessCommandLine startswith "smbd -D")
| where not (FolderPath in~ ("/usr/sbin/","/usr/local/samba/sbin/","/opt/samba/sbin/"))
  or not (InitiatingProcessFileName in~ ("systemd","init","smbd"))
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### GS-Netcat reverse shell beaconing to gs.thc.org with systemd or rc-script persistence

`UC_1_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.All_Traffic.dest="gs.thc.org" OR Network_Traffic.All_Traffic.dest_host="gs.thc.org" OR Network_Traffic.All_Traffic.url="*gs.thc.org*" OR Network_Traffic.All_Traffic.query="*gs.thc.org*") by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.src_ip Network_Traffic.All_Traffic.dest Network_Traffic.All_Traffic.app | `drop_dm_object_name(Network_Traffic.All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let beacons = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "gs.thc.org" or RemoteUrl endswith ".thc.org"
    | project Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, ProcessFile=InitiatingProcessFileName, ProcessPath=InitiatingProcessFolderPath, ProcessCmd=InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort;
let persist = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified")
    | where FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/etc/init.d/","/etc/rc.local","/etc/profile.d/","/root/.bashrc","/etc/bash.bashrc")
    | project PersistTime=Timestamp, DeviceId, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
beacons
| join kind=leftouter persist on DeviceId
| where isnull(PersistTime) or abs(datetime_diff('hour', PersistTime, Timestamp)) <= 24
| project Timestamp, DeviceName, AccountName, ProcessFile, ProcessPath, ProcessCmd, RemoteUrl, RemoteIP, RemotePort, PersistTime, FolderPath, FileName, SHA256
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
