# [CRIT] Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication

**Source:** The Hacker News, Cyber Security News
**Published:** 2026-06-13
**Article:** https://thehackernews.com/2026/06/critical-splunk-enterprise-flaw-lets.html

## Threat Profile

Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication 
 Ravie Lakshmanan  Jun 13, 2026 Vulnerability / Enterprise Software 
Splunk has released security updates to address a critical security flaw in Splunk Enterprise that could be exploited to conduct unauthenticated file operations and even remote code execution.
The vulnerability, tracked as CVE-2026-20253 , is rated 9.8 on the CVSS scoring system.
"In Splunk Enterprise versions below 10.2.4 and 10.0.7, an unauthent…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20253`

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
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505.003** — Server Software Component: Web Shell
- **T1574** — Hijack Execution Flow
- **T1219** — Remote Access Software
- **T1592.004** — Gather Victim Host Information: Client Configurations
- **T1595.002** — Active Scanning: Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated POST to Splunk /v1/postgres/recovery/{backup,restore} endpoints

`UC_9_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.status) as status values(Web.http_user_agent) as ua from datamodel=Web where (Web.url="*/v1/postgres/recovery/backup*" OR Web.url="*/v1/postgres/recovery/restore*") Web.status>=200 Web.status<300 by Web.src Web.dest Web.url Web.http_method | `drop_dm_object_name(Web)` | iplocation src | search NOT src IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("splunkd.exe","splunkd","postgres","postgres.exe")
| where RemotePort in (8089, 8000)
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("/v1/postgres/recovery/backup","/v1/postgres/recovery/restore",".pgpass","postgres_admin")
  ) on DeviceId
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### splunkd spawning shell interpreters (CVE-2026-20253 post-exploit RCE)

`UC_9_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("splunkd","splunkd.exe","splunk","splunk.exe")) Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","python","python3","perl","ruby","nc","ncat","curl","wget") by host Processes.parent_process_name Processes.process_name Processes.process_path Processes.user | `drop_dm_object_name(Processes)` | where NOT match(cmdline,"(?i)(modinput|scripted_input|splunk_secure_gateway[/\\\\]bin[/\\\\]ssg_enable_modular_input\\.py|splunk-launch|btool)") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("splunkd.exe","splunkd","splunk.exe","splunk")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","python.exe","python","python3","perl.exe","perl","ruby.exe","ruby","nc.exe","ncat.exe","curl.exe","wget.exe")
| where not(ProcessCommandLine has_any ("ssg_enable_modular_input.py","splunk-launch","btool","scripted_input","modinput"))
   or ProcessCommandLine has_any ("-EncodedCommand","base64","/dev/tcp/","socket.","connect_back","reverse","bash -i","curl http","wget http")
| project Timestamp, DeviceName, AccountName,
          ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Write to Splunk .pgpass or ssg_enable_modular_input.py from unexpected process

`UC_9_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user values(Filesystem.action) as action from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/opt/splunk/var/packages/data/postgres/.pgpass*" OR Filesystem.file_path="*/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py*") Filesystem.action IN ("created","modified","written","renamed") by host Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT (proc IN ("postgres","splunkd-package-mgr") AND file_path LIKE "%.pgpass") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/opt/splunk/var/packages/data/postgres/","\\Splunk\\var\\packages\\data\\postgres\\","/opt/splunk/etc/apps/splunk_secure_gateway/bin/","\\Splunk\\etc\\apps\\splunk_secure_gateway\\bin\\")
| where FileName in~ (".pgpass","ssg_enable_modular_input.py")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("postgres","postgres.exe","splunk-package-installer")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Splunk Enterprise host initiating outbound PostgreSQL (TCP/5432) to public IP

`UC_9_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.bytes_out) as bytes_out values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=5432 All_Traffic.action=allowed by All_Traffic.src All_Traffic.dest All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | iplocation dest | search NOT dest IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12") | join src [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("splunkd","splunkd.exe") by host | rename host as src | fields src] | sort - lastTime
```

**Defender KQL:**
```kql
let SplunkHosts = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("splunkd.exe","splunkd","splunk.exe","splunk")
    | distinct DeviceId, DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 5432
| where RemoteIPType == "Public"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| join kind=inner SplunkHosts on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, LocalIP, LocalPort
| order by Timestamp desc
```

### Splunk Enterprise vulnerable version inventory (CVE-2026-20253 exposure)

`UC_9_11` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("splunkd","splunkd.exe") by host Processes.process_path | `drop_dm_object_name(Processes)` | rex field=process_path "(?i)splunk[\\\\/](?<version>\d+\.\d+\.\d+)" | where (match(version,"^10\.0\.(0|1|2|3|4|5|6)$") OR match(version,"^10\.2\.(0|1|2|3)$")) | stats values(version) as affected_version values(process_path) as splunk_path by host
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "splunk" or SoftwareName has "splunk"
| where SoftwareName has "enterprise" or SoftwareName has_any ("splunkd","Splunk Enterprise")
| extend MajorMinorPatch = extract(@"(\d+\.\d+\.\d+)", 1, SoftwareVersion)
| extend MajorMinor = extract(@"(\d+\.\d+)", 1, SoftwareVersion)
| extend PatchNum = toint(extract(@"\d+\.\d+\.(\d+)", 1, SoftwareVersion))
| where (MajorMinor == "10.0" and PatchNum between (0 .. 6))
      or (MajorMinor == "10.2" and PatchNum between (0 .. 3))
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, MajorMinorPatch
| union (
    DeviceTvmSoftwareVulnerabilities
    | where CveId == "CVE-2026-20253"
    | project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, MajorMinorPatch=SoftwareVersion
)
| distinct DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion
```

### Reconnaissance probes to Splunk version/info endpoints

`UC_9_12` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.http_user_agent) as ua dc(Web.url) as distinct_urls from datamodel=Web where (Web.url="*/services/server/info*" OR Web.url="*/en-US/about*" OR Web.url="*/static/js/build/version*" OR Web.url="*/services/auth/login*" OR Web.url="*/en-US/account/login*") Web.status IN (200,401,403) by Web.src Web.dest _time span=1h | `drop_dm_object_name(Web)` | iplocation src | search NOT src IN ("10.0.0.0/8","192.168.0.0/16","172.16.0.0/12") | where count >= 3 OR distinct_urls >= 2 | sort - _time
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (8000, 8089)
| where InitiatingProcessFileName !in~ ("splunkd.exe","splunkd","chrome.exe","msedge.exe","firefox.exe")
| summarize HitCount = count(),
            DistinctPaths = dcount(RemoteUrl),
            UAs = make_set(InitiatingProcessVersionInfoProductName, 5)
            by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where HitCount >= 5
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

### Article-specific behavioural hunt — Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication

`UC_9_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/splunk/var/packages/data/postgres/.pgpass*" OR Filesystem.file_path="*/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/splunk/var/packages/data/postgres/.pgpass", "/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20253`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 13 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
