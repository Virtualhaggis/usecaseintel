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
- **T1556** — Modify Authentication Process
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1505.003** — Server Software Component: Web Shell
- **T1090.001** — Proxy: Internal Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant — Unauthorized modification of PAM modules on Linux

`UC_151_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.process_path) as proc_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/lib/security/*","/lib64/security/*","/usr/lib/security/*","/usr/lib/x86_64-linux-gnu/security/*","/usr/lib64/security/*") OR Filesystem.file_name IN ("pam_unix.so","pam_sss.so","pam_ldap.so","pam_systemd.so","pam_deny.so","pam_permit.so")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path Filesystem.action | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(dpkg|rpm|yum|dnf|apt|apt-get|zypper|pacman|systemd-tmpfiles|debsums)$") | where action IN ("created","modified","renamed")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName !endswith "$"
| where FolderPath has_any ("/lib/security/","/lib64/security/","/usr/lib/security/","/usr/lib/x86_64-linux-gnu/security/","/usr/lib64/security/")
   or FileName in~ ("pam_unix.so","pam_sss.so","pam_ldap.so","pam_systemd.so","pam_deny.so","pam_permit.so","pam_tally2.so","pam_faillock.so")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","systemd-tmpfiles","debsums","dpkg-deb")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Velvet Ant — Unauthorized modification of sshd/ssh binaries

`UC_151_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.process_path) as proc_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/ssh-keygen","/usr/bin/ssh-agent","/usr/bin/scp","/usr/bin/sftp","/usr/libexec/openssh/*","/etc/ssh/sshd_config") Filesystem.action IN ("created","modified","renamed") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(dpkg|rpm|yum|dnf|apt|apt-get|zypper|pacman)$")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath in~ ("/usr/sbin/","/usr/bin/","/usr/libexec/openssh/","/etc/ssh/")
| where FileName in~ ("sshd","ssh","ssh-keygen","ssh-agent","scp","sftp","sftp-server","ssh-keysign","sshd_config")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade","yum-cron","dnf-automatic")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, MD5,
          PreviousFileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant — Suspicious child process from sshd / su / sudo / login

`UC_151_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("sshd","su","sudo","login") AND Processes.process_name IN ("curl","wget","nc","ncat","netcat","socat","gcc","cc","g++","make","python","python2","python3","perl","ruby","base64","openssl","xxd","chattr","setcap") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | where NOT match(cmdline,"(?i)(ansible|salt-minion|puppet|chef-client)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("sshd","su","sudo","login","systemd-logind")
| where FileName in~ ("curl","wget","nc","ncat","netcat","socat","gcc","cc","g++","make","python","python2","python3","perl","ruby","base64","openssl","xxd","chattr","setcap","setsid","nohup")
| where InitiatingProcessTokenElevation in~ ("TokenElevationTypeFull","TokenElevationTypeDefault")
| where AccountName !in~ ("ansible","saltuser","_apt","deploy")
| where InitiatingProcessParentFileName !in~ ("ansible-playbook","salt-minion","puppet","chef-client")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Velvet Ant — ld.so.preload or LD_PRELOAD persistence on Linux

`UC_151_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/etc/ld.so.preload","/etc/profile","/etc/environment","/etc/bashrc","/etc/bash.bashrc","/etc/pam.d/*","/root/.bashrc","/root/.bash_profile","/root/.profile") Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(dpkg|rpm|yum|dnf|apt|apt-get|zypper|pacman|systemd-tmpfiles)$")
```

**Defender KQL:**
```kql
union
(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath == "/etc/" and FileName == "ld.so.preload"
  | extend Signal = "ld.so.preload write"
),
(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where (FolderPath == "/etc/" and FileName in~ ("profile","environment","bashrc","bash.bashrc"))
     or (FolderPath startswith "/etc/pam.d/")
     or (FolderPath has "/.bashrc" or FolderPath has "/.bash_profile" or FolderPath has "/.profile")
  | extend Signal = "shell rc / pam.d write"
)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","systemd-tmpfiles","useradd","usermod")
| project Timestamp, DeviceName, Signal, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant — Outbound network connections initiated by sshd or PAM-loaded process

`UC_151_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("sshd","su","sudo","login") AND All_Traffic.direction="outbound" by All_Traffic.src All_Traffic.process_name All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip) AND NOT cidrmatch("192.168.0.0/16",dest_ip) | where dest_port!=22
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("sshd","su","sudo","login")
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemoteIPType == "Public"
| where RemotePort != 22
| where not(InitiatingProcessCommandLine has_any ("-R ","-L ","-W "))
| project Timestamp, DeviceName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName,
          RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Velvet Ant — Internet-facing web server spawning interactive shell or SSH child

`UC_151_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("httpd","nginx","php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","java","tomcat","w3wp.exe","apache2","caddy") AND Processes.process_name IN ("bash","sh","dash","zsh","ssh","scp","sftp","nc","ncat","socat","python","python3","perl","chisel","frpc","ngrok","plink.exe","cmd.exe","powershell.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("httpd","nginx","apache2","php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","java","tomcat","w3wp.exe","caddy")
| where FileName in~ ("bash","sh","dash","zsh","ssh","scp","sftp","nc","ncat","socat","python","python3","perl","chisel","frpc","ngrok","plink.exe","cmd.exe","powershell.exe","pwsh.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
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

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
