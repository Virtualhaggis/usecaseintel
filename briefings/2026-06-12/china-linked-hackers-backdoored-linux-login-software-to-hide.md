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
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1556.003** — Modify Authentication Process: PAM
- **T1056.001** — Input Capture: Keylogging
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1090.001** — Internal Proxy
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **T1014** — Rootkit
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unexpected modification of PAM module or OpenSSH binary on Linux

`UC_6_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action=modified AND (Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/sudo","/bin/su","/usr/bin/su") OR Filesystem.file_path="/lib/security/*" OR Filesystem.file_path="/lib64/security/*" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/*" OR Filesystem.file_path="*/pam_unix.so" OR Filesystem.file_path="*/pam_sshd.so" OR Filesystem.file_path="*/pam_tally2.so") AND NOT Filesystem.process_name IN ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade") by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceInfo has "Linux" or FolderPath startswith "/"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has_any ("/lib/security/","/lib64/security/","/lib/x86_64-linux-gnu/security/","/usr/lib/security/") and FileName endswith ".so")
   or FolderPath in ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/sudo","/bin/su","/usr/bin/su","/usr/sbin/sshd-session")
   or FileName in~ ("pam_unix.so","pam_sshd.so","pam_tally2.so","pam_permit.so","pam_deny.so","sshd","sudo")
| where InitiatingProcessFileName !in~ ("dpkg","apt","apt-get","yum","dnf","rpm","zypper","unattended-upgrade","snapd","dnf-automatic","livepatch")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Authentication-subsystem process initiating outbound network connection (auth-stage C2)

`UC_6_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic where All_Traffic.dest_category!="internal" AND (All_Traffic.process_name IN ("sshd","su","sudo","login","sshd-session") OR All_Traffic.process_path IN ("/usr/sbin/sshd","/usr/bin/sudo","/bin/su","/usr/bin/su")) by All_Traffic.src All_Traffic.process_name All_Traffic.user | `drop_dm_object_name(All_Traffic)` | where dest_port!=22 | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("sshd","sshd-session","su","sudo","login")
   or InitiatingProcessFolderPath in ("/usr/sbin/sshd","/usr/bin/sudo","/bin/su","/usr/bin/su")
| where RemotePort !in (22, 443)  // SSH outbound to peer is legit for ProxyJump; allow then filter
   or (RemotePort == 443 and InitiatingProcessFileName in~ ("sshd","su","sudo"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Credential-logging string or hidden-switch flag in sshd/PAM binary on disk

`UC_6_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_hash) as observed_hash from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/sudo","/bin/su") OR Filesystem.file_path="*/pam_unix.so" OR Filesystem.file_path="*/pam_sshd.so" by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | lookup distro_pkg_hashes file_path OUTPUT expected_hash | where observed_hash != expected_hash
```

**Defender KQL:**
```kql
let AuthBinaries = dynamic(["/usr/sbin/sshd","/usr/bin/ssh","/usr/bin/sudo","/bin/su","/usr/bin/su"]);
let PamModulePaths = dynamic(["/lib/security/","/lib64/security/","/lib/x86_64-linux-gnu/security/","/usr/lib/security/"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath in (AuthBinaries)
   or (FolderPath has_any (PamModulePaths) and FileName endswith ".so")
| summarize HashCount = dcount(SHA256), Hashes = make_set(SHA256, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, FolderPath, FileName
| where HashCount > 1  // hash drift on a binary that shouldn't change between package updates
| order by LastSeen desc
```

### Internet-facing web server spawning interactive shell or SSH client to internal segment

`UC_6_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as child_path values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("httpd","nginx","apache2","java","tomcat","node","php-fpm","uwsgi","gunicorn") AND Processes.process_name IN ("bash","sh","dash","zsh","ssh","scp","socat","ncat","nc") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("httpd","nginx","apache2","java","tomcat","node","php-fpm","uwsgi","gunicorn","w3wp.exe")
| where FileName in~ ("bash","sh","dash","zsh","ssh","scp","socat","ncat","nc","python3","perl")
| where ProcessCommandLine has_any (" -i"," -e ","bash -i","/dev/tcp/","socat ","-R ","-L ","DynamicForward","ProxyCommand")
   or FileName in~ ("ssh","scp")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Authentication-binary file hash differs from installed package's expected hash (RPM/DEB verify)

`UC_6_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=linux_syslog (sourcetype="linux:secure" OR sourcetype="linux:syslog") ("rpm -V" OR debsums OR "prelink" OR "file hash mismatch") (sshd OR sudo OR "pam_unix" OR "pam_sshd" OR "/bin/su") ("S.5." OR "FAILED" OR "changed") | rex "(?<verify_flags>[S.][M.][5.][D.][L.][U.][G.][T.])\s+(?<bin_path>\S+)" | where like(verify_flags,"%5%") | stats count min(_time) as firstTime max(_time) as lastTime by host, bin_path, verify_flags | sort - firstTime
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileIntegrityMonitoringEvent","PackageVerificationFailed")
   or AdditionalFields has_any ("rpm -V","debsums","S.5")
| where AdditionalFields has_any ("sshd","sudo","pam_unix","pam_sshd","/bin/su","libpam")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, AdditionalFields
| order by Timestamp desc
```

### Suspicious kernel module load on Linux host running tampered auth binary

`UC_6_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("insmod","modprobe","kmod") AND NOT Processes.parent_process_name IN ("systemd","systemd-modules-load","udevd","udev","dracut","mkinitcpio","NetworkManager") by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("insmod","modprobe","kmod")
| where InitiatingProcessFileName !in~ ("systemd","systemd-modules-load","udevd","udevadm","dracut","mkinitcpio","NetworkManager","docker","containerd","kubelet")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath in ("/usr/sbin/sshd","/usr/bin/sudo","/bin/su") or (FolderPath has "/security/" and FileName endswith ".so")
    | summarize HashCount = dcount(SHA256) by DeviceName
  ) on DeviceName
| extend SuspicionScore = case(HashCount > 1, "high", "baseline")
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

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
