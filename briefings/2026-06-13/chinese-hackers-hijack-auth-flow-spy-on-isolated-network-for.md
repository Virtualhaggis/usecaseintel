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
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Proxy: Internal Proxy
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1556.002** — Modify Authentication Process: Password Filter DLL
- **T1556** — Modify Authentication Process
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1056.001** — Input Capture: Keylogging
- **T1555** — Credentials from Password Stores
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant GS-Netcat C2 callback to gs.thc.org from Linux server processes

`UC_2_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("gs.thc.org","*.gs.thc.org","*.thc.org") by DNS.src DNS.query DNS.dest DNS.answer host | `drop_dm_object_name(DNS)` | where NOT match(src,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.).*_devworkstation$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith "gs.thc.org" or RemoteUrl endswith ".thc.org"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### SOCKS5 proxy daemon masquerading as 'smbd -D' from non-Samba path

`UC_2_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="smbd" (Processes.process="*-D*" OR Processes.process="*--daemon*") by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name Processes.parent_process_path host | `drop_dm_object_name(Processes)` | where NOT match(process_path,"^/(usr/sbin|usr/local/sbin|opt/samba/sbin)/smbd$") OR NOT match(parent_process_name,"^(systemd|init|smbd)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "smbd"
| where ProcessCommandLine has "-D" or ProcessCommandLine has "--daemon"
| where not(FolderPath in~ ("/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd"))
      or not(InitiatingProcessFileName in~ ("systemd","init","smbd"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### fcgiwrap spawning ssh/scp/uptime — Velvet Ant air-gapped pivot chain

`UC_2_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="fcgiwrap" Processes.process_name IN ("ssh","scp","sftp","nc","ncat","socat","uptime","bash","sh","dash") by Processes.dest Processes.user Processes.parent_process_path Processes.parent_process Processes.process_name Processes.process_path Processes.process host | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "fcgiwrap"
| where FileName in~ ("ssh","scp","sftp","nc","ncat","socat","uptime","bash","sh","dash")
   or (FileName =~ "uptime" and not(FolderPath in~ ("/usr/bin/uptime","/bin/uptime")))
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Backdoored pam_unix.so written outside of package-manager activity

`UC_2_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/usr/lib/security/*" OR Filesystem.file_path="/usr/lib64/security/*" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/*" OR Filesystem.file_name IN ("pam_unix.so","pam_sss.so","pam_winbind.so","pam_ldap.so","pam_krb5.so")) Filesystem.action IN ("created","modified","renamed") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action Filesystem.process_name host | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"^(dpkg|rpm|yum|dnf|apt|apt-get|zypper|pacman|unattended-upgrade|unattended-upgrades|update-alternatives)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/lib/security/","/lib64/security/","/usr/lib/security/","/usr/lib64/security/","/lib/x86_64-linux-gnu/security/")
   or FileName in~ ("pam_unix.so","pam_sss.so","pam_winbind.so","pam_ldap.so","pam_krb5.so","pam_tally2.so")
| where not(InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade","unattended-upgrades","update-alternatives","rpm-ostree"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binaries (sshd/ssh/scp/sftp) overwritten outside of package-manager

`UC_2_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/bin/sftp","/usr/libexec/openssh/sftp-server","/usr/lib/openssh/sftp-server","/usr/local/sbin/sshd","/usr/local/bin/ssh","/usr/local/bin/scp")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action Filesystem.process_name host | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"^(dpkg|rpm|yum|dnf|apt|apt-get|zypper|pacman|unattended-upgrade|unattended-upgrades|update-alternatives|rpm-ostree)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/usr/sbin/","/usr/bin/","/usr/local/sbin/","/usr/local/bin/","/usr/libexec/openssh/","/usr/lib/openssh/")
      and FileName in~ ("sshd","ssh","scp","sftp","sftp-server","ssh-agent","ssh-keygen","ssh-keyscan")
| where not(InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade","unattended-upgrades","update-alternatives","rpm-ostree"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### systemd .service unit created with ExecStart pointing to non-standard binary

`UC_2_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="/lib/systemd/system/*" OR Filesystem.file_path="/etc/rc.d/*" OR Filesystem.file_path="/etc/init.d/*" OR Filesystem.file_name IN ("rc.local")) (Filesystem.file_name="*.service" OR Filesystem.file_name="rc.local") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action Filesystem.process_name host | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"^(dpkg|rpm|yum|dnf|apt|apt-get|zypper|pacman|unattended-upgrade|unattended-upgrades|systemctl|systemd-sysv-install|cloud-init|snapd)$") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/lib/systemd/system/","/etc/systemd/user/")
         and FileName endswith ".service")
     or FolderPath has_any ("/etc/rc.d/","/etc/init.d/","/etc/profile.d/","/etc/cron.d/")
     or FileName in~ ("rc.local",".bashrc",".bash_profile",".profile")
| where not(InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade","unattended-upgrades","systemctl","systemd-sysv-install","cloud-init","snapd","rpm-ostree"))
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
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
