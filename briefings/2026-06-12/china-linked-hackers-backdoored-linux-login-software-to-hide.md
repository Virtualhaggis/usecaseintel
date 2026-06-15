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
- **T1056.001** — Input Capture: Keylogging
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1133** — External Remote Services
- **T1021.004** — Remote Services: SSH
- **T1090.001** — Proxy: Internal Proxy
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthorized write to Linux PAM authentication module (pam_unix.so swap)

`UC_43_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/lib/security/pam_*.so" OR Filesystem.file_path="*/lib64/security/pam_*.so" OR Filesystem.file_path="*/lib/x86_64-linux-gnu/security/pam_*.so" OR Filesystem.file_path="*/usr/lib64/security/pam_*.so" OR Filesystem.file_path="*/usr/lib/x86_64-linux-gnu/security/pam_*.so") Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("dpkg","dpkg-deb","apt","apt-get","aptitude","unattended-upgrade","yum","dnf","rpm","zypper","pacman","ldconfig","snapd") by Filesystem.dest Filesystem.process_name Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort 0 - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"/lib/security/", @"/lib64/security/", @"/lib/x86_64-linux-gnu/security/", @"/usr/lib/x86_64-linux-gnu/security/", @"/usr/lib64/security/")
| where FileName startswith "pam_" and FileName endswith ".so"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","dpkg-deb","apt","apt-get","aptitude","unattended-upgrade","yum","dnf","rpm","zypper","pacman","ldconfig","snapd","snap")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, MD5, PreviousFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Unauthorized modification of OpenSSH sshd or ssh client binary

`UC_43_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/sshd","/usr/bin/ssh","/usr/sbin/ssh","/usr/bin/ssh-keygen","/usr/bin/scp","/usr/bin/sftp") Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("dpkg","dpkg-deb","apt","apt-get","unattended-upgrade","yum","dnf","rpm","zypper","pacman") by Filesystem.dest Filesystem.process_name Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort 0 - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath in~ ("/usr/sbin/","/usr/bin/")
| where FileName in~ ("sshd","ssh","ssh-keygen","scp","sftp","ssh-agent")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","dpkg-deb","apt","apt-get","unattended-upgrade","yum","dnf","rpm","zypper","pacman","snapd","snap")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, MD5, PreviousFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### sshd writing to non-standard files (credential-capture log artifact)

`UC_43_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name from datamodel=Endpoint.Filesystem where Filesystem.process_name="sshd" Filesystem.action IN ("created","modified") NOT (Filesystem.file_path IN ("/var/run/sshd.pid","/run/sshd.pid","/var/log/auth.log","/var/log/secure","/var/log/lastlog","/var/log/wtmp","/var/log/btmp","/var/log/utmp","/run/utmp","/var/empty/sshd") OR Filesystem.file_path="/home/*/.ssh/*" OR Filesystem.file_path="/root/.ssh/*" OR Filesystem.file_path="/tmp/ssh-*" OR Filesystem.file_path="/var/lib/sss/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort 0 - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "sshd"
| where InitiatingProcessFolderPath in~ ("/usr/sbin/","/usr/bin/")
| where ActionType in ("FileCreated","FileModified")
| where not (FolderPath in~ ("/var/run/","/run/","/var/log/","/var/empty/sshd/","/var/lib/sss/") )
| where not (FolderPath startswith "/home/" and FolderPath contains "/.ssh/")
| where not (FolderPath startswith "/root/.ssh/")
| where not (FolderPath startswith "/tmp/ssh-")
| where FileName !in~ ("sshd.pid","auth.log","secure","lastlog","wtmp","btmp","utmp")
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RequestAccountName
| order by Timestamp desc
```

### Internet-facing web service spawning interactive SSH into management subnet

`UC_43_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("httpd","nginx","apache2","tomcat","java","node","php-fpm","php-cgi","uwsgi","gunicorn","caddy","haproxy","lighttpd") Processes.process_name IN ("ssh","sshpass","scp","sftp","plink","autossh","socat","ncat","nc") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | sort 0 - lastTime
```

**Defender KQL:**
```kql
let WebParents = dynamic(["httpd","nginx","apache2","tomcat","java","node","php-fpm","php-cgi","uwsgi","gunicorn","caddy","lighttpd","haproxy"]);
let PivotTools = dynamic(["ssh","sshpass","scp","sftp","plink","autossh","socat","ncat","nc"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (WebParents)
| where FileName in~ (PivotTools)
| extend RfcTarget = extract(@"(?:^|\s)(?:-[a-zA-Z]\s+)?(?:[A-Za-z0-9_\-]+@)?((?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+\.\d+|(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+)", 1, ProcessCommandLine)
| where isnotempty(RfcTarget) or ProcessCommandLine has_any (".internal",".corp",".local",".lan",".intranet")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RfcTarget, InitiatingProcessParentFileName
| order by Timestamp desc
```

### First-seen pam_unix.so / sshd / ssh binary hash in Linux fleet

`UC_43_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.dest) as hosts from datamodel=Endpoint.Processes where Processes.process_name IN ("sshd","ssh","scp","sftp") earliest=-60d@d latest=-7d@d by Processes.process_hash Processes.process_name | `drop_dm_object_name(Processes)` | rename process_hash as baseline_hash | append [ | tstats summariesonly=t count min(_time) as recent_firstTime max(_time) as recent_lastTime values(Processes.dest) as recent_hosts from datamodel=Endpoint.Processes where Processes.process_name IN ("sshd","ssh","scp","sftp") earliest=-7d@d by Processes.process_hash Processes.process_name | `drop_dm_object_name(Processes)` | rename process_hash as recent_hash ] | stats values(*) as * by recent_hash | where isnotnull(recent_hash) AND isnull(baseline_hash)
```

**Defender KQL:**
```kql
let Lookback = 60d;
let Recent = 7d;
let AuthBinaries = dynamic(["sshd","ssh","scp","sftp","ssh-keygen","ssh-agent"]);
let BaselineExec = DeviceProcessEvents
    | where Timestamp between (ago(Lookback) .. ago(Recent))
    | where FileName in~ (AuthBinaries) and FolderPath in~ ("/usr/sbin/","/usr/bin/")
    | summarize by SHA256, FileName;
let RecentExec = DeviceProcessEvents
    | where Timestamp > ago(Recent)
    | where FileName in~ (AuthBinaries) and FolderPath in~ ("/usr/sbin/","/usr/bin/")
    | summarize FirstSeen = min(Timestamp), HostCount = dcount(DeviceId), AnyHost = any(DeviceName), AnyCmd = any(ProcessCommandLine) by SHA256, FileName, FolderPath;
let NewExec = RecentExec | join kind=leftanti BaselineExec on SHA256, FileName | extend Kind = "sshd/ssh exec";
let BaselineLoad = DeviceImageLoadEvents
    | where Timestamp between (ago(Lookback) .. ago(Recent))
    | where FileName == "pam_unix.so"
    | summarize by SHA256, FileName;
let RecentLoad = DeviceImageLoadEvents
    | where Timestamp > ago(Recent)
    | where FileName == "pam_unix.so"
    | summarize FirstSeen = min(Timestamp), HostCount = dcount(DeviceId), AnyHost = any(DeviceName), AnyCmd = "" by SHA256, FileName, FolderPath;
let NewLoad = RecentLoad | join kind=leftanti BaselineLoad on SHA256, FileName | extend Kind = "pam_unix.so load";
union NewExec, NewLoad
| order by FirstSeen desc
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

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
