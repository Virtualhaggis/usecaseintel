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


Dubbed "Operation Highland," the intrusion is attributed to the Velvet Ant cyberespionage threat group, which targeted vulnerable internet-facing systems before pivoting to a network with no direct externa…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1554** — Compromise Host Software Binary
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1056.001** — Input Capture: Keylogging
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Proxy: Internal Proxy
- **T1090.002** — Proxy: External Proxy
- **T1505.003** — Server Software Component: Web Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1021.004** — Remote Services: SSH
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Linux pam_unix.so module replaced outside package management (Velvet Ant PAM backdoor)

`UC_0_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") (Filesystem.file_path="/lib/security/pam_unix.so" OR Filesystem.file_path="/lib64/security/pam_unix.so" OR Filesystem.file_path="/usr/lib/security/pam_unix.so" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/pam_unix.so" OR Filesystem.file_path="/usr/lib/x86_64-linux-gnu/security/pam_unix.so") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path Filesystem.user | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any (@"/lib/security/", @"/lib64/security/", @"/usr/lib/security/", @"/lib/x86_64-linux-gnu/security/", @"/usr/lib/x86_64-linux-gnu/security/")
| where FileName startswith "pam_" and FileName endswith ".so"
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "pacman", "unattended-upgrade", "packagekitd"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### OpenSSH binaries (sshd/ssh/scp) overwritten outside package management

`UC_0_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") (Filesystem.file_path="/usr/sbin/sshd" OR Filesystem.file_path="/usr/bin/ssh" OR Filesystem.file_path="/usr/bin/scp" OR Filesystem.file_path="/usr/sbin/ssh" OR Filesystem.file_path="/usr/local/sbin/sshd" OR Filesystem.file_path="/usr/local/bin/ssh") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path Filesystem.user | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath in~ (@"/usr/sbin/", @"/usr/bin/", @"/usr/local/sbin/", @"/usr/local/bin/", @"/bin/", @"/sbin/")
| where FileName in~ ("sshd", "ssh", "scp", "sftp-server")
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "pacman", "unattended-upgrade", "packagekitd"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Process command line 'smbd -D' from non-Samba binary path (masqueraded SOCKS5 proxy)

`UC_0_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as process_path values(Processes.process_name) as process_name values(Processes.parent_process_name) as parent_process_name values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process="*smbd -D*" NOT (Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd","/usr/bin/smbd")) NOT (Processes.process_name="smbd" AND Processes.process_path IN ("/usr/sbin/smbd","/usr/local/sbin/smbd")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "smbd -D" or ProcessCommandLine has "smbd --daemon"
| where not(FolderPath in~ ("/usr/sbin/", "/usr/local/sbin/", "/usr/bin/", "/usr/local/bin/"))
  or not(FileName =~ "smbd")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Nginx configuration file modified outside package management (fcgiwrap/uptime backdoor pivot)

`UC_0_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") (Filesystem.file_path="/etc/nginx/nginx.conf" OR Filesystem.file_path="/etc/nginx/conf.d/*" OR Filesystem.file_path="/etc/nginx/sites-available/*" OR Filesystem.file_path="/etc/nginx/sites-enabled/*" OR Filesystem.file_path="/etc/nginx/fastcgi*" OR Filesystem.file_path="/usr/local/nginx/conf/*") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","ansible","salt-minion","puppetd","chef-client","cf-agent","certbot")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path Filesystem.user | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath startswith "/etc/nginx" or FolderPath startswith "/usr/local/nginx/conf" or FolderPath startswith "/usr/local/openresty/nginx/conf"
| where FileName endswith ".conf" or FileName startswith "fastcgi" or FileName == "nginx.conf"
| where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "pacman", "unattended-upgrade", "ansible", "salt-minion", "puppet", "puppetd", "chef-client", "cf-agent", "certbot", "nginx"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### fcgiwrap or nginx-user process spawning SSH or non-web child binary

`UC_0_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name="fcgiwrap" OR Processes.parent_process_name="nginx" OR Processes.user IN ("www-data","nginx","apache","http")) (Processes.process_name="ssh" OR Processes.process_name="scp" OR Processes.process_name="sshpass" OR Processes.process_name="bash" OR Processes.process_name="sh" OR Processes.process_name="dash" OR Processes.process_name="uptime") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("fcgiwrap", "nginx")
  or InitiatingProcessAccountName in~ ("www-data", "nginx", "apache", "http", "httpd")
| where FileName in~ ("ssh", "scp", "sshpass", "bash", "sh", "dash", "zsh", "uptime", "nc", "ncat", "socat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### New systemd unit or rc.local hook spawning long-lived encrypted outbound (GS-Netcat reverse shell persistence)

`UC_0_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/lib/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="/etc/rc.local" OR Filesystem.file_path="/etc/init.d/*" OR Filesystem.file_path="/etc/rc*.d/*") (Filesystem.file_name="*.service" OR Filesystem.file_name="rc.local" OR Filesystem.file_path="/etc/init.d/*") NOT (Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","systemd","systemctl","ansible","salt-minion","puppetd","chef-client","cf-agent")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path Filesystem.user | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let SuspiciousUnitWrites = DeviceFileEvents
  | where Timestamp > ago(7d)
  | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
  | where (FolderPath startswith "/etc/systemd/system" or FolderPath startswith "/lib/systemd/system" or FolderPath startswith "/usr/lib/systemd/system")
     or FolderPath == "/etc/" and FileName == "rc.local"
     or FolderPath startswith "/etc/init.d"
     or FolderPath startswith "/etc/rc.d"
  | where not(InitiatingProcessFileName in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "zypper", "pacman", "systemd", "systemctl", "ansible", "salt-minion", "puppet", "chef-client", "cf-agent"))
  | project FileWriteTime = Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA256,
            InitiatingProcessFileName, InitiatingProcessAccountName;
let LongLivedNetwork = DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where ActionType == "ConnectionSuccess"
  | where RemoteIPType == "Public"
  | where RemotePort in (443, 53, 80, 8443, 8080)
  | project NetTime = Timestamp, DeviceId, RemoteIP, RemoteUrl, RemotePort,
            InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
            InitiatingProcessAccountName;
SuspiciousUnitWrites
| join kind=inner LongLivedNetwork on DeviceId
| where NetTime between (FileWriteTime .. FileWriteTime + 1h)
| project FileWriteTime, NetTime, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessFileName1 = InitiatingProcessFileName1,
          RemoteIP, RemoteUrl, RemotePort,
          NetCmd = InitiatingProcessCommandLine1
| order by FileWriteTime desc
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


## Why this matters

Severity classified as **CRIT** based on: 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
