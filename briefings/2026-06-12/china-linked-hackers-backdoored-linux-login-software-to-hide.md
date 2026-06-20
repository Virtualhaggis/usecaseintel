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
- **T1556.004** — Modify Authentication Process: Network Device Authentication
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1055.008** — Process Injection: Ptrace System Calls
- **T1056.002** — Input Capture: GUI Input Capture
- **T1090.001** — Proxy: Internal Proxy
- **T1572** — Protocol Tunneling
- **T1505.003** — Server Software Component: Web Shell
- **T1068** — Exploitation for Privilege Escalation
- **T1505** — Server Software Component
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1584.008** — Compromise Infrastructure: Network Devices

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velvet Ant: PAM module file modification under /lib/security or /etc/pam.d

`UC_151_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/lib/security/*.so","/lib64/security/*.so","/usr/lib/security/*.so","/usr/lib64/security/*.so","/etc/pam.d/sshd","/etc/pam.d/login","/etc/pam.d/system-auth","/etc/pam.d/password-auth","/etc/pam.d/common-auth","/etc/pam.d/common-password")) AND Filesystem.action IN ("created","modified","renamed") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/lib/security/","/lib64/security/","/usr/lib/security/","/usr/lib64/security/","/etc/pam.d/")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade","PackageKit","systemd-update-helper")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          ActorProc = InitiatingProcessFileName,
          ActorCmd  = InitiatingProcessCommandLine,
          ActorUser = InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant: OpenSSH binary or /etc/ssh config replacement outside package-manager change

`UC_151_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/ssh-agent","/usr/bin/sshd","/etc/ssh/sshd_config","/etc/ssh/sshd_config.d/*","/etc/ssh/ssh_config")) AND Filesystem.action IN ("created","modified","renamed") AND NOT Filesystem.process_name IN ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath in~ ("/usr/sbin/","/usr/bin/") and FileName in~ ("sshd","ssh","ssh-agent","ssh-keygen"))
   or  FolderPath has "/etc/ssh/"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","zypper","pacman","unattended-upgrade","PackageKit")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          ActorProc = InitiatingProcessFileName,
          ActorCmd  = InitiatingProcessCommandLine,
          ActorUser = InitiatingProcessAccountName
| order by Timestamp desc
```

### Velvet Ant: sshd or /bin/login spawning shell-tier child not in baseline

`UC_151_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("sshd","login","sshd-session")) AND Processes.process_name IN ("curl","wget","nc","ncat","socat","base64","openssl","python","python3","perl","php","ruby","bash","sh","dash") AND (Processes.process IN ("*-c *","*base64*","*--decode*","*s_client*","*-e /bin/*","*tcp:*","*/dev/tcp/*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("sshd","login","sshd-session")
| where FileName in~ ("curl","wget","nc","ncat","socat","base64","openssl","python","python3","perl","php","ruby")
   or ProcessCommandLine has_any ("/dev/tcp/"," -e /bin/","base64 -d","openssl s_client","bash -i","sh -i")
| where AccountName !in~ ("root") or ProcessCommandLine has_any ("/dev/tcp/","base64 -d","bash -i","openssl s_client")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          ChildPath = FolderPath,
          SHA256
| order by Timestamp desc
```

### Velvet Ant: ptrace/debugger attached to live sshd or login process for credential capture

`UC_151_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("strace","ltrace","gdb","gcore") AND (Processes.process IN ("*-p *","*--pid*","*attach *")) AND (Processes.process IN ("*sshd*","*login*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("strace","ltrace","gdb","gcore")
| where ProcessCommandLine has_any ("-p ","--pid","attach ")
| where ProcessCommandLine has_any ("sshd","/bin/login"," login ")
   or ProcessCommandLine matches regex @"-p\s+\d+"
| where InitiatingProcessTokenElevation =~ "TokenElevationTypeFull"
   or AccountName == "root"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Tool = FileName,
          ToolCmd = ProcessCommandLine,
          Elev = InitiatingProcessTokenElevation
| order by Timestamp desc
```

### Velvet Ant: internet-facing web server proxying SSH/shell into isolated network segment

`UC_151_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("httpd","apache2","nginx","php-fpm","php-fpm7.4","php-fpm8.1","java","tomcat","node","w3wp")) AND Processes.process_name IN ("ssh","sshpass","plink","socat","chisel","frpc","ngrok","ligolo") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let WebSrv = dynamic(["httpd","apache2","nginx","php-fpm","php-fpm7.4","php-fpm8.1","java","tomcat","node","w3wp"]);
let Tunnel = dynamic(["ssh","sshpass","plink","socat","chisel","frpc","ngrok","ligolo","3proxy"]);
let TunnelProcs =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ (WebSrv)
    | where FileName in~ (Tunnel)
    | project ChildTime = Timestamp, DeviceId, DeviceName,
              Parent = InitiatingProcessFileName,
              ParentCmd = InitiatingProcessCommandLine,
              Child = FileName,
              ChildCmd = ProcessCommandLine,
              ChildPid = ProcessId;
TunnelProcs
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteIPType == "Private"
    | where RemotePort in (22, 2222, 3389, 445)
    | project NetTime = Timestamp, DeviceId, RemoteIP, RemotePort,
              InitiatingProcessId, InitiatingProcessFileName
  ) on DeviceId
| where InitiatingProcessId == ChildPid
| where NetTime between (ChildTime .. ChildTime + 5m)
| project ChildTime, NetTime, DeviceName, Parent, ParentCmd, Child, ChildCmd, RemoteIP, RemotePort
| order by ChildTime desc
```

### Velvet Ant: Cisco NX-OS exec command exploiting CVE-2024-20399 admin->bash escape

`UC_151_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cisco_nxos` (eventtype=cisco_nxos_aaa OR sourcetype="cisco:nxos:syslog") (message="*run bash*" OR message="*python*" OR message="*feature bash-shell*" OR command="run bash*" OR command="python*") | stats min(_time) as firstTime max(_time) as lastTime values(command) as commands values(src_ip) as src_ip by host user
```

### Velvet Ant: F5 BIG-IP unexpected outbound management-plane connection

`UC_151_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_category="f5_mgmt" AND All_Traffic.action="allowed" AND NOT All_Traffic.dest_port IN (53,123,443,514,6514) AND NOT All_Traffic.dest IN ("f5_iquery_peers","ntp_pool","big_iq_servers") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
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

Severity classified as **CRIT** based on: CVE present, 13 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
