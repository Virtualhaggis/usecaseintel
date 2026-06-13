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
- **T1556.003** — Pluggable Authentication Modules
- **T1554** — Compromise Host Software Binary
- **T1027** — Obfuscated Files or Information
- **T1556** — Modify Authentication Process
- **T1040** — Network Sniffing
- **T1543.002** — Systemd Service
- **T1037.004** — RC Scripts
- **T1036.005** — Match Legitimate Name or Location
- **T1090.001** — Internal Proxy
- **T1572** — Protocol Tunneling
- **T1505.003** — Web Shell
- **T1021.004** — SSH
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### PAM module replacement — backdoored pam_unix.so write to /lib*/security

`UC_2_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/usr/lib/security/*" OR Filesystem.file_path="/usr/lib64/security/*" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/*") AND Filesystem.file_name IN ("pam_unix.so","pam_sshd.so","pam_systemd.so","pam_tally2.so","pam_deny.so") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","packagekitd") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"/lib/security/", @"/lib64/security/", @"/usr/lib/security/", @"/usr/lib64/security/", @"/lib/x86_64-linux-gnu/security/")
| where FileName has_any ("pam_unix.so","pam_sshd.so","pam_systemd.so","pam_tally2.so","pam_deny.so","pam_env.so")
| where not (InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","packagekitd","rpmdb","unattended-upgr"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### OpenSSH binary replacement — ssh/sshd/scp written by non-package process

`UC_2_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path IN ("/usr/bin/ssh","/usr/bin/scp","/usr/bin/ssh-keygen","/usr/bin/ssh-agent","/usr/sbin/sshd","/usr/local/bin/ssh","/usr/local/sbin/sshd")) AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","packagekitd","unattended-upgr") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"/usr/bin/", @"/usr/sbin/", @"/usr/local/bin/", @"/usr/local/sbin/", @"/bin/", @"/sbin/")
| where FileName in~ ("ssh","sshd","scp","ssh-agent","ssh-keygen","sftp-server")
| where not (InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","packagekitd","unattended-upgr","snapd"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Systemd unit drops with ExecStart pointing to non-system path (GS-Netcat persistence)

`UC_2_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="/lib/systemd/system/*" OR Filesystem.file_path="/etc/rc.local" OR Filesystem.file_path="/etc/init.d/*") AND (Filesystem.file_name="*.service" OR Filesystem.file_name="*.timer" OR Filesystem.file_name="rc.local") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","packagekitd","systemctl") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"/etc/systemd/system/", @"/usr/lib/systemd/system/", @"/lib/systemd/system/", @"/etc/init.d/", @"/etc/rc.local", @"/root/.bashrc", @"/etc/profile.d/")
| where (FileName endswith ".service" or FileName endswith ".timer" or FileName == "rc.local" or FileName endswith ".sh")
| where not (InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","packagekitd","systemctl","systemd","snapd"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Nginx config modified with fcgiwrap upstream or proxy chain into RFC1918 host

`UC_2_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="/etc/nginx/*" OR Filesystem.file_path="/usr/local/nginx/conf/*" OR Filesystem.file_path="/etc/nginx/sites-enabled/*" OR Filesystem.file_path="/etc/nginx/sites-available/*" OR Filesystem.file_path="/etc/nginx/conf.d/*") AND (Filesystem.file_name="*.conf" OR Filesystem.file_name="nginx.conf") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","packagekitd","certbot","nginx") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"/etc/nginx/", @"/etc/nginx/conf.d/", @"/etc/nginx/sites-enabled/", @"/etc/nginx/sites-available/", @"/usr/local/nginx/conf/", @"/usr/local/etc/nginx/")
| where (FileName endswith ".conf" or FileName == "nginx.conf")
| where not (InitiatingProcessFileName in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","packagekitd","certbot","nginx","snapd"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### SOCKS5 proxy masquerading as 'smbd -D' from non-Samba binary path

`UC_2_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="smbd*-D*" OR Processes.process_name="smbd") AND NOT (Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd","/usr/local/samba/sbin/smbd")) by Processes.dest Processes.process_name Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine startswith "smbd " or ProcessCommandLine has "smbd -D"
| where not (FolderPath in~ ("/usr/sbin/smbd","/usr/local/sbin/smbd","/opt/samba/sbin/smbd","/usr/local/samba/sbin/smbd"))
| extend ParentLooksLikeSystemd = (InitiatingProcessFileName in~ ("systemd","init","smbd"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ParentLooksLikeSystemd
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
