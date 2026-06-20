# [CRIT] China-Linked Hackers Backdoored Linux Login Software to Hide for Nearly a Decade

**Source:** The Hacker News
**Published:** 2026-06-12
**Article:** https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html

## Threat Profile

China-Linked Hackers Backdoored Linux Login Software to Hide for Nearly a Decade 
 Swati Khandelwal  Jun 12, 2026 Linux / Network Security 
Instead of hiding on the laptops and servers defenders watch most closely, a China-nexus group spent close to a decade hidden inside the Linux login system itself.
Sygnia, which tracks the group as Velvet Ant , says it backdoored the PAM and OpenSSH components that decide who is allowed to sign in, planting its access where ordinary cleanup could not reach…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-20399`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1554** — Compromise Host Software Binary
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1556.004** — Modify Authentication Process: Network Device Authentication
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1095** — Non-Application Layer Protocol
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1548.001** — Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1556.003** — Modify Authentication Process: PAM
- **T1090.001** — Proxy: Internal Proxy
- **T1505.003** — Server Software Component: Web Shell
- **T1059** — Command and Scripting Interpreter
- **T1601.001** — Modify System Image: Patch System Image
- **T1078.001** — Valid Accounts: Default Accounts
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant: PAM Module or /etc/pam.d Config Tampering Outside Package Manager

`UC_153_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/lib/security/*","/lib64/security/*","/usr/lib/security/*","/usr/lib64/security/*","/usr/lib/x86_64-linux-gnu/security/*","/etc/pam.d/*") OR Filesystem.file_name IN ("pam_unix.so","pam_sss.so","pam_tally2.so","pam_systemd.so","pam_securetty.so","pam_deny.so","pam_permit.so")) Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","unattended-upgrade","packagekitd") by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceId in ((DeviceInfo | where OSPlatform in ("Linux","Ubuntu","RHEL","CentOS","Debian","SUSE") | distinct DeviceId))
| where FolderPath matches regex @"^/(usr/)?lib(64|/x86_64-linux-gnu)?/security/.*\.so$"
     or FolderPath startswith "/etc/pam.d/"
     or FileName in ("pam_unix.so","pam_sss.so","pam_tally2.so","pam_systemd.so","pam_securetty.so","pam_deny.so","pam_permit.so")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","unattended-upgrade","packagekitd","PackageKit")
| where InitiatingProcessParentFileName !in~ ("dpkg","apt","apt-get","yum","dnf","unattended-upgrade")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, PreviousFolderPath, PreviousFileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Velvet Ant: OpenSSH Daemon Binary or sshd_config Modified Outside Package Manager

`UC_153_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/ssh-agent","/usr/bin/ssh-keygen","/usr/sbin/sshd-session","/etc/ssh/sshd_config","/etc/ssh/ssh_config") OR Filesystem.file_path="/etc/ssh/sshd_config.d/*") Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","unattended-upgrade") by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceId in ((DeviceInfo | where OSPlatform in ("Linux","Ubuntu","RHEL","CentOS","Debian","SUSE") | distinct DeviceId))
| where FolderPath in ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/ssh-agent","/usr/bin/ssh-keygen","/usr/sbin/sshd-session","/etc/ssh/sshd_config","/etc/ssh/ssh_config")
     or FolderPath startswith "/etc/ssh/sshd_config.d/"
     or (FileName == "sshd" and FolderPath startswith "/usr/sbin")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","apt-get","yum","dnf","zypper","pacman","unattended-upgrade","packagekitd")
| where InitiatingProcessParentFileName !in~ ("dpkg","apt","apt-get","yum","dnf","unattended-upgrade")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Velvet Ant: sshd or login Process Initiating Outbound Network Connections

`UC_153_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.app IN ("sshd","login") OR All_Traffic.process_name IN ("sshd","login","/usr/sbin/sshd","/bin/login","/usr/bin/login") All_Traffic.direction="outbound" NOT All_Traffic.dest_ip IN ("127.0.0.0/8","::1") by All_Traffic.src All_Traffic.process_name All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceId in ((DeviceInfo | where OSPlatform in ("Linux","Ubuntu","RHEL","CentOS","Debian","SUSE") | distinct DeviceId))
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where InitiatingProcessFileName in~ ("sshd","login","sshd-session")
     or InitiatingProcessFolderPath in ("/usr/sbin/sshd","/bin/login","/usr/bin/login","/usr/sbin/sshd-session")
| where RemoteIPType != "Loopback"
| where not(RemoteIP startswith "127.")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessParentFileName,
          LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType, RemoteUrl, Protocol
| order by Timestamp desc
```

### Velvet Ant: Unexpected Child Process Spawned by sshd or login (Non-Shell, Non-Session)

`UC_153_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("sshd","login","sshd-session") NOT Processes.process_name IN ("bash","sh","zsh","fish","tcsh","ksh","dash","systemd","systemd-user-runtime-dir","pam_systemd","unix_chkpwd","sftp-server","sshd","login","scp","rsync","id","hostname","motd-news","update-motd","pam_motd","who","w","last","lastlog","mesg","tmux","screen") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in ((DeviceInfo | where OSPlatform in ("Linux","Ubuntu","RHEL","CentOS","Debian","SUSE") | distinct DeviceId))
| where InitiatingProcessFileName in~ ("sshd","login","sshd-session")
| where FileName !in~ ("bash","sh","zsh","fish","tcsh","ksh","dash","systemd","systemd-user-runtime-dir","pam_systemd","unix_chkpwd","sftp-server","sshd","login","scp","rsync","id","hostname","motd-news","update-motd","pam_motd","who","w","last","lastlog","mesg","tmux","screen","env","locale","groups")
| where FileName !startswith "motd"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine, SHA256, ProcessIntegrityLevel
| order by Timestamp desc
```

### Velvet Ant: Web Server Process Spawning Reverse Shell or Long-Running ssh/nc Pipe

`UC_153_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("httpd","nginx","apache2","php-fpm","php-fpm7.4","php-fpm8.1","tomcat","java","node","caddy","lighttpd") Processes.process_name IN ("ssh","nc","ncat","socat","bash","sh","python","python3","perl","ruby","chisel","frpc","gost","sshuttle") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in ((DeviceInfo | where OSPlatform in ("Linux","Ubuntu","RHEL","CentOS","Debian","SUSE") | distinct DeviceId))
| where InitiatingProcessFileName in~ ("httpd","nginx","apache2","php-fpm","php-fpm7.4","php-fpm8.1","tomcat","java","node","caddy","lighttpd")
| where FileName in~ ("ssh","nc","ncat","socat","bash","sh","python","python3","perl","ruby","chisel","frpc","gost","sshuttle")
| where ProcessCommandLine has_any ("-R ","-L ","-D ","-e /bin/","-e /usr/","/dev/tcp/","socket.socket","pty.spawn","sh -i","bash -i","--reverse","connect-back")
     or InitiatingProcessAccountName in~ ("www-data","nginx","apache","httpd","tomcat","daemon")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessAccountName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Cisco NX-OS CVE-2024-20399 Exploitation Indicators on Nexus Switch Syslog

`UC_153_11` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cisco_nexus` sourcetype IN ("cisco:nxos","cisco:nxos:syslog") (eventtype="cisco_nexus_run_bash" OR "run bash" OR "feature bash-shell" OR "copy bootflash:" OR "load bootflash:" OR "install activate" OR "copy scp:") | rex field=_raw "user[:=]\s*(?<user>[^\s,]+)" | rex field=_raw "from\s+(?<src_ip>(?:\d{1,3}\.){3}\d{1,3})" | stats count min(_time) as firstTime max(_time) as lastTime values(_raw) as raw by host user src_ip | where count > 0
```

### Velvet Ant: PAM/sshd Memory Read of /etc/shadow or libc Credential Functions

`UC_153_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(`linux_auditd` (type=PATH name="/etc/shadow" OR name="/etc/gshadow") OR (`linux_auditd` type=EXECVE comm IN ("sshd","login") (a0="/proc" OR a1="/proc")) OR (`linux_auditd` type=SYSCALL syscall=ptrace comm IN ("sshd","login"))) | stats count min(_time) as firstTime max(_time) as lastTime values(comm) as comm values(exe) as exe values(name) as file by host pid auid uid | where count > 0
```

**Defender KQL:**
```kql
let SuspectAuthReads = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("sshd","login","sshd-session")
    | where FolderPath in ("/etc/shadow","/etc/gshadow","/etc/security/opasswd") or FolderPath startswith "/proc/" and FolderPath endswith "/mem"
    | where ActionType in ("FileOpened","FileAccessed","FileModified");
let LdPreloadApplied = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("sshd","login","sshd-session")
    | where ProcessCommandLine has "LD_PRELOAD" or InitiatingProcessCommandLine has "LD_PRELOAD"
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine;
SuspectAuthReads
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| union LdPreloadApplied
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-20399`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 13 use case(s) fired, 28 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
