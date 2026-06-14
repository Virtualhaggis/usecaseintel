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
- **T1573** — Encrypted Channel
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1556** — Modify Authentication Process
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1056.001** — Input Capture: Keylogging
- **T1572** — Protocol Tunneling
- **T1021.004** — Remote Services: SSH
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1090** — Proxy
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GS-Netcat reverse shell beacon to thc.org relay (Velvet Ant Operation Highland)

`UC_2_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution.DNS where DNS.query="*.thc.org" OR DNS.query="gs.thc.org" by DNS.query DNS.src host
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| append [| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_category="gs.thc.org" OR All_Traffic.dest="*thc.org*" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
// GS-Netcat relay (gs.thc.org) — Velvet Ant Operation Highland
let relay_domains = dynamic(["gs.thc.org","thc.org"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (relay_domains)) or (RemoteUrl endswith ".thc.org")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### Linux PAM module (pam_unix.so) replaced outside package manager — Velvet Ant auth backdoor

`UC_2_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/*" OR Filesystem.file_path="/usr/lib/x86_64-linux-gnu/security/*" OR Filesystem.file_name="pam_unix.so" OR Filesystem.file_name="pam_deny.so" OR Filesystem.file_name="pam_permit.so") Filesystem.action IN ("created","modified","write") NOT (Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","unattended-upgr","snap","snapd","puppet","chef-client","ansible-playbook","salt-minion")) by host Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// PAM module replacement — Operation Highland persistence
let pkg_mgrs = dynamic(["dpkg","apt","apt-get","yum","dnf","rpm","unattended-upgr","snap","snapd","puppet","chef-client","ansible-playbook","salt-minion","cfengine"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/lib/security/","/lib64/security/","/lib/x86_64-linux-gnu/security/","/usr/lib/x86_64-linux-gnu/security/","/usr/lib64/security/")
    or FileName in~ ("pam_unix.so","pam_deny.so","pam_permit.so","pam_env.so","pam_tally2.so","pam_faillock.so")
| where InitiatingProcessFileName !in~ (pkg_mgrs)
| where InitiatingProcessCommandLine !has "dpkg-trigger"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileSize, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binary (sshd/ssh/scp) replaced outside package manager — Velvet Ant trojanization

`UC_2_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/libexec/openssh/sftp-server","/usr/lib/openssh/sftp-server","/usr/bin/ssh-agent","/usr/bin/ssh-keygen")) Filesystem.action IN ("created","modified","renamed") NOT (Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","unattended-upgr","snap","snapd","puppet","chef-client","ansible-playbook","salt-minion")) by host Filesystem.file_path Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// OpenSSH trojanization — Velvet Ant Operation Highland
let ssh_paths = dynamic(["/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/scp","/usr/libexec/openssh/sftp-server","/usr/lib/openssh/sftp-server","/usr/bin/ssh-agent","/usr/bin/ssh-keygen","/usr/bin/sftp"]);
let pkg_mgrs = dynamic(["dpkg","apt","apt-get","yum","dnf","rpm","unattended-upgr","snap","snapd","puppet","chef-client","ansible-playbook","salt-minion"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where strcat(FolderPath,"/",FileName) in~ (ssh_paths)
    or (FolderPath has_any ("/usr/sbin","/usr/bin","/usr/libexec/openssh","/usr/lib/openssh") and FileName in~ ("sshd","ssh","scp","sftp-server","ssh-agent","ssh-keygen","sftp"))
| where InitiatingProcessFileName !in~ (pkg_mgrs)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileSize, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### fcgiwrap or Nginx spawning ssh / shell — Operation Highland air-gap pivot

`UC_2_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("fcgiwrap","nginx") OR Processes.parent_process="*fcgiwrap*") Processes.process_name IN ("ssh","scp","sh","bash","dash","nc","ncat","socat","uptime","python","python3","perl") by host Processes.parent_process_name Processes.process_name Processes.user dest
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Nginx/fcgiwrap pivot chain — Operation Highland air-gap bridge
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("fcgiwrap","nginx","nginx: worker")
    or InitiatingProcessParentFileName in~ ("fcgiwrap","nginx")
    or InitiatingProcessCommandLine has "fcgiwrap"
| where FileName in~ ("ssh","scp","sftp","sh","bash","dash","nc","ncat","socat","uptime","python","python3","perl")
    or ProcessCommandLine has_any ("ssh ","sshpass","ProxyJump","ProxyCommand","StrictHostKeyChecking=no")
| project Timestamp, DeviceName, AccountName, ParentImage = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine, ChildImage = FolderPath, ChildName = FileName, ChildCmd = ProcessCommandLine, SHA256, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Process masquerading as 'smbd -D' from non-Samba path — Velvet Ant SOCKS5 daemon

`UC_2_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as path values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process="*smbd -D*" by host Processes.process_name Processes.process_path Processes.parent_process_name Processes.user dest
| `drop_dm_object_name(Processes)`
| where NOT match(path,"^/usr/sbin/smbd$") AND NOT match(path,"^/usr/bin/smbd$")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// smbd -D masquerade — Operation Highland SOCKS5 proxy
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"(^|/| )smbd\s+-D(\s|$)"
| where not (FolderPath in~ ("/usr/sbin","/usr/bin","/usr/local/sbin") and FileName =~ "smbd")
    or InitiatingProcessFileName !in~ ("systemd","init","smbd","samba-ad-dc","sh","bash")
| extend SuspiciousReason = case(
    FolderPath !in~ ("/usr/sbin","/usr/bin","/usr/local/sbin"), "smbd running from non-system path",
    InitiatingProcessFileName !in~ ("systemd","init","smbd"), strcat("parent is ", InitiatingProcessFileName),
    "other")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SuspiciousReason
| order by Timestamp desc
```

### Linux persistence: systemd unit / rc.local written by non-package process referencing world-writable or temp paths

`UC_2_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="/lib/systemd/system/*" OR Filesystem.file_path="/etc/rc.local" OR Filesystem.file_path="/etc/init.d/*" OR Filesystem.file_path="/etc/profile.d/*") Filesystem.action IN ("created","modified") NOT (Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","unattended-upgr","snap","snapd","systemctl","systemd","puppet","chef-client","ansible-playbook","salt-minion","cloud-init")) by host Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Linux persistence: systemd / rc.local written outside package manager — Operation Highland GS-Netcat persistence
let pkg_mgrs = dynamic(["dpkg","apt","apt-get","yum","dnf","rpm","unattended-upgr","snap","snapd","systemctl","systemd","systemd-tmpfile","puppet","chef-client","ansible-playbook","salt-minion","cloud-init"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/lib/systemd/system/","/etc/init.d/","/etc/profile.d/","/etc/cron.d/")
    or (FolderPath == "/etc" and FileName in~ ("rc.local","profile","bashrc"))
| where InitiatingProcessFileName !in~ (pkg_mgrs)
| where InitiatingProcessCommandLine !has "dpkg-trigger"
| extend SuspiciousAccount = (InitiatingProcessAccountName !in~ ("root","_apt","_unbound"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileSize, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SuspiciousAccount
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 9 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
