# [HIGH] Hackers Compromised 233 Versions of Laravel-Lang Packages by Hacking 700 GitHub Repos

**Source:** Cyber Security News
**Published:** 2026-05-23
**Article:** https://cybersecuritynews.com/laravel-lang-packages-compromised/

## Threat Profile

Home Cyber Security 
Hackers Compromised 233 Versions of Laravel-Lang Packages by Hacking 700 GitHub Repos 
By Guru Baran 
May 23, 2026 
A highly sophisticated supply chain attack has compromised the Laravel-Lang ecosystem, injecting credential-stealing remote code execution backdoors into 233 package versions across 700 GitHub repositories.
Discovered in May 2026 by Socket and Aikido, threat actors manipulated GitHub tags to distribute malware through Composer’s autoloader, granting complete re…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `flipboxstudio.info`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1041** — Exfiltration Over C2 Channel
- **T1059.004** — Unix Shell
- **T1036.005** — Match Legitimate Name or Location
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1552.005** — Cloud Instance Metadata API
- **T1083** — File and Directory Discovery
- **T1078.004** — Cloud Accounts
- **T1195.001** — Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Laravel-Lang stealer C2 callback to flipboxstudio.info from PHP/web runtime

`UC_5_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.src) as src values(All_Traffic.app) as process values(All_Traffic.url) as url from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="flipboxstudio.info" OR All_Traffic.url="*flipboxstudio.info*" OR All_Traffic.url="*/payload*" OR All_Traffic.url="*/exfil*") by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where DNS.query="flipboxstudio.info" OR DNS.query="*.flipboxstudio.info" by DNS.src DNS.query | `drop_dm_object_name(DNS)`] | where count > 0
```

**Defender KQL:**
```kql
let C2Domain = "flipboxstudio.info";
let WebRuntimes = dynamic(["php.exe","php-cgi.exe","php-fpm","php","httpd","apache2","nginx","w3wp.exe","cscript.exe","wscript.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has C2Domain
   or RemoteUrl has "/payload"
   or RemoteUrl has "/exfil"
| where InitiatingProcessFileName in~ (WebRuntimes)
   or InitiatingProcessParentFileName in~ (WebRuntimes)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] Composer autoload triggers PHP child process dropping stealer to /tmp/.laravel_locale

`UC_5_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent_proc from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("php","php-fpm","php-cgi","httpd","apache2","nginx","php.exe","php-cgi.exe") AND Processes.process_name IN ("php","php.exe") AND (Processes.process="*.laravel_locale*" OR Processes.process="*helpers.php*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where count > 0
```

**Defender KQL:**
```kql
let WebParents = dynamic(["php","php-fpm","php-cgi","php.exe","php-cgi.exe","httpd","apache2","nginx","w3wp.exe"]);
let ChildPhp = dynamic(["php","php.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (WebParents)
| where FileName in~ (ChildPhp)
| where ProcessCommandLine has ".laravel_locale"
    or ProcessCommandLine has "helpers.php"
    or ProcessCommandLine matches regex @"\.laravel_locale[\\/][0-9a-f]{12}\.php"
| project Timestamp, DeviceName, AccountName,
          ParentImage=InitiatingProcessFolderPath,
          ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] cscript.exe launches .vbs from .laravel_locale temp directory (Windows dropper stage)

`UC_5_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name="cscript.exe" AND (Processes.process="*\\.laravel_locale\\*" OR Processes.process="*.laravel_locale*" OR Processes.process="*DebugChromium.exe*") by host Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | where count > 0
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "cscript.exe"
| where ProcessCommandLine has ".laravel_locale"
    or ProcessCommandLine matches regex @"(?i)\\\.laravel_locale\\[0-9a-f]{8}\.vbs"
    or InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","w3wp.exe")
        and ProcessCommandLine has ".vbs"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Sensitive credential file enumeration by PHP/web user (cloud, SSH, k8s, vault)

`UC_5_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.git-credentials" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/.bash_history" OR Filesystem.file_path="*/Login Data" OR Filesystem.file_path="*\\Login Data") AND (Filesystem.process_name IN ("php","php-fpm","php-cgi","httpd","apache2","nginx","php.exe","w3wp.exe","cscript.exe")) by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | stats dc(file_path) as distinct_secret_files values(file_path) as files by host user process_name | where distinct_secret_files >= 3
```

**Defender KQL:**
```kql
let SecretPaths = dynamic(["/.aws/credentials","/.aws/config","/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.kube/config","/.docker/config.json","/.git-credentials","/.vault-token","/.bash_history","/.zsh_history","Login Data","Login.keychain","wallet.dat"]);
let WebRuntimes = dynamic(["php","php-fpm","php-cgi","httpd","apache2","nginx","php.exe","php-cgi.exe","w3wp.exe","cscript.exe","wscript.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileAccessed")
| where InitiatingProcessFileName in~ (WebRuntimes)
| where FolderPath has_any (SecretPaths) or FileName in~ ("credentials","config","id_rsa","id_ed25519","config.json",".git-credentials",".vault-token","Login Data","wallet.dat")
| summarize FirstSeen=min(Timestamp), DistinctSecrets=dcount(FolderPath), SampleFiles=make_set(FolderPath, 10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| where DistinctSecrets >= 2
```

### [LLM] Web-runtime process queries cloud instance metadata service (169.254.169.254)

`UC_5_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as process values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="169.254.169.254" AND All_Traffic.app IN ("php","php-fpm","php-cgi","php.exe","httpd","apache2","nginx","w3wp.exe","cscript.exe","wscript.exe") by host All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let WebRuntimes = dynamic(["php","php-fpm","php-cgi","php.exe","php-cgi.exe","httpd","apache2","nginx","w3wp.exe","cscript.exe","wscript.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName in~ (WebRuntimes)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### [LLM] composer.lock or composer.json change adding laravel-lang package on developer/CI host

`UC_5_13` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name="composer.lock" OR Filesystem.file_name="composer.json") AND Filesystem.action IN ("created","modified","written") by host Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=inner host [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process_name="composer" OR Processes.process="*composer*require*laravel-lang*" OR Processes.process="*composer*update*laravel-lang*" OR Processes.process="*composer*install*" by host Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("composer.lock","composer.json")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("composer","composer.phar","composer.exe","php","php.exe")
    | where ProcessCommandLine has "laravel-lang"
       or ProcessCommandLine has "composer" and ProcessCommandLine has_any ("install","update","require")
    | project DeviceName, ProcCmd=ProcessCommandLine, ProcTime=Timestamp
) on DeviceName
| where ProcTime between (Timestamp - 5m .. Timestamp + 5m)
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName, ProcCmd
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

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Hackers Compromised 233 Versions of Laravel-Lang Packages by Hacking 700 GitHub

`UC_5_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Compromised 233 Versions of Laravel-Lang Packages by Hacking 700 GitHub ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("debugchromium.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("debugchromium.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Compromised 233 Versions of Laravel-Lang Packages by Hacking 700 GitHub
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("debugchromium.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("debugchromium.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `flipboxstudio.info`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
