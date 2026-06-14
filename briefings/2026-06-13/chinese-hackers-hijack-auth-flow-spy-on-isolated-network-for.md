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
- **T1555** — Credentials from Password Stores
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1090** — Proxy
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573** — Encrypted Channel
- **T1090.002** — Proxy: External Proxy
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Linux PAM module replacement (pam_unix.so) outside package manager — Velvet Ant persistence

`UC_4_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/lib/security/*","/lib64/security/*","/usr/lib/security/*","/usr/lib64/security/*","/lib/x86_64-linux-gnu/security/*")) (Filesystem.file_name IN ("pam_unix.so","pam_sss.so","pam_ldap.so","pam_krb5.so","pam_winbind.so","pam_systemd.so")) Filesystem.action IN ("created","modified","renamed") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","rpm-ostree") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"/lib/security/", @"/lib64/security/", @"/usr/lib/security/", @"/usr/lib64/security/", @"/lib/x86_64-linux-gnu/security/")
| where FileName in~ ("pam_unix.so","pam_sss.so","pam_ldap.so","pam_krb5.so","pam_winbind.so","pam_systemd.so","pam_tally2.so","pam_faillock.so")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","rpm-ostree","snapd")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binary tamper (sshd/ssh/scp) outside package manager — Velvet Ant credential capture

`UC_4_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/*","/usr/bin/*","/usr/local/sbin/*","/usr/local/bin/*")) (Filesystem.file_name IN ("sshd","ssh","scp","sftp-server","ssh-agent","ssh-keygen","ssh-keyscan")) Filesystem.action IN ("created","modified","renamed") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","update-alternatives","rpm-ostree") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/usr/sbin/","/usr/bin/","/usr/local/sbin/","/usr/local/bin/","/bin/","/sbin/")
| where FileName in~ ("sshd","ssh","scp","sftp-server","ssh-agent","ssh-keygen","ssh-keyscan","ssh-add")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","update-alternatives","rpm-ostree","snapd","unattended-upgrade")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### fcgiwrap spawning ssh/nc/uptime — Nginx→FastCGI air-gap pivot bridge

`UC_4_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="fcgiwrap" Processes.process_name IN ("ssh","scp","sftp","nc","ncat","socat","uptime","bash","sh","dash","python","python3","perl","curl","wget") by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "fcgiwrap"
| where FileName in~ ("ssh","scp","sftp","nc","ncat","socat","uptime","bash","sh","dash","python","python3","perl","curl","wget")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ParentParent = InitiatingProcessParentFileName,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### smbd -D process anomaly — Velvet Ant SOCKS5 proxy masquerade

`UC_4_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*smbd*-D*" OR Processes.process_name="smbd") by Processes.dest Processes.user Processes.process Processes.process_name Processes.process_path Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | search NOT (process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd")) OR NOT (parent_process_name IN ("systemd","init","smbd","smbcontrol")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "smbd" and ProcessCommandLine matches regex @"(?i)\bsmbd\b.*\s-D\b"
| where not (FolderPath in~ ("/usr/sbin/","/usr/local/sbin/") and FileName =~ "smbd" and InitiatingProcessFileName in~ ("systemd","init","smbd","smbcontrol"))
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Outbound resolution/connection to gs.thc.org — GS-Netcat C2 relay

`UC_4_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="gs.thc.org" OR DNS.query="*.gs.thc.org" OR DNS.query="*.thc.org") by DNS.src DNS.dest DNS.query DNS.answer DNS.src_user | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="gs.thc.org" OR All_Traffic.dest_host="gs.thc.org") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
union
(
  DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any ("gs.thc.org",".thc.org") or RemoteUrl endswith "thc.org"
  | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, Protocol,
            InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
            InitiatingProcessAccountName, InitiatingProcessParentFileName
),
(
  DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has "gs.thc.org" or AdditionalFields has "thc.org"
  | project Timestamp, DeviceName, AdditionalFields,
            InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
)
| order by Timestamp desc
```

### New systemd unit with ExecStart pointing to non-standard binary path

`UC_4_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/etc/systemd/system/*","/usr/lib/systemd/system/*","/lib/systemd/system/*","/etc/init.d/*","/etc/rc.local")) (Filesystem.file_name="*.service" OR Filesystem.file_name="*.timer" OR Filesystem.file_name="rc.local") Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","systemctl","systemd-tmpfiles","snapd","rpm-ostree") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (@"/etc/systemd/system/", @"/usr/lib/systemd/system/", @"/lib/systemd/system/", @"/etc/init.d/")
   or FileName =~ "rc.local"
| where FileName endswith ".service" or FileName endswith ".timer" or FileName =~ "rc.local"
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","systemctl","systemd","systemd-tmpfiles","snapd","rpm-ostree","unattended-upgrade")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
