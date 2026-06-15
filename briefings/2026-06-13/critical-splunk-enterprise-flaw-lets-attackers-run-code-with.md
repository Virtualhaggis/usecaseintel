# [CRIT] Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication

**Source:** The Hacker News
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
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1595.002** — Active Scanning: Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CVE-2026-20253: Unauthorized write to ssg_enable_modular_input.py by non-Splunk

`UC_17_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py", "/opt/splunk/var/packages/data/postgres/.pgpass") AND Filesystem.action IN ("created","modified","write","rename") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | where NOT (process_name IN ("rpm","dpkg","apt","yum","tar","unzip","splunk")) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath in~ ("/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py", "/opt/splunk/var/packages/data/postgres/.pgpass")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where not (InitiatingProcessFileName in~ ("rpm", "dpkg", "apt-get", "yum", "dnf", "tar", "unzip", "splunk"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, ActionType, SHA256
| order by Timestamp desc
```

### CVE-2026-20253: Unauthenticated POST to /v1/postgres/recovery/backup or /restore

`UC_17_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user_agent) as user_agents values(Web.status) as statuses from datamodel=Web where Web.url="*/v1/postgres/recovery/backup*" OR Web.url="*/v1/postgres/recovery/restore*" by Web.src Web.dest Web.dest_port Web.url Web.http_method | `drop_dm_object_name(Web)` | where http_method="POST" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 8089
| where ActionType in ("InboundConnectionAccepted", "ConnectionSuccess")
| where RemoteUrl has_any ("/v1/postgres/recovery/backup", "/v1/postgres/recovery/restore")
   or AdditionalFields has_any ("/v1/postgres/recovery/backup", "/v1/postgres/recovery/restore")
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, RemoteUrl, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

### CVE-2026-20253: splunkd spawning shell or interpreter child process

`UC_17_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as child_path from datamodel=Endpoint.Processes where (Processes.parent_process_name="splunkd" OR Processes.parent_process_path="/opt/splunk/bin/splunkd" OR Processes.parent_process IN ("*ssg_enable_modular_input.py*")) AND Processes.process_name IN ("bash","sh","dash","zsh","nc","ncat","socat","curl","wget","perl") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | where (match(cmdline,"(?i)(/dev/tcp/|bash -i|sh -i|nc .* -e|/tmp/\.|curl .* \| (bash|sh)|wget .* \| (bash|sh)|python3? -c|base64 -d)")) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "splunkd"
   or InitiatingProcessCommandLine has "ssg_enable_modular_input.py"
| where FileName in~ ("bash", "sh", "dash", "zsh", "nc", "ncat", "socat", "curl", "wget", "perl")
| where ProcessCommandLine has_any ("/dev/tcp/", "bash -i", "sh -i", "-e /bin/", "/tmp/.", "python -c", "python3 -c", "base64 -d", "| bash", "| sh")
   or ProcessCommandLine matches regex @"(?i)curl\s+(-[A-Za-z]+\s+)*https?://[^\s]+\s*\|\s*(bash|sh)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### CVE-2026-20253: Vulnerable Splunk Enterprise version exposed

`UC_17_10` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| inputlookup splunk_enterprise_inventory.csv | eval major=tonumber(mvindex(split(version,"."),0)), minor=tonumber(mvindex(split(version,"."),1)), patch=tonumber(mvindex(split(version,"."),2)) | where (major=10 AND minor=0 AND patch<7) OR (major=10 AND minor=2 AND patch<4) | table host version os last_seen owner
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "splunk"
| where SoftwareName has "enterprise"
| extend Parts = split(SoftwareVersion, ".")
| extend Major = toint(Parts[0]), Minor = toint(Parts[1]), Patch = toint(Parts[2])
| where (Major == 10 and Minor == 0 and Patch < 7) or (Major == 10 and Minor == 2 and Patch < 4)
| project DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, Major, Minor, Patch
| order by DeviceName asc
```

### CVE-2026-20253: External scan for Splunk management interface (port 8089)

`UC_17_11` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.dest) as distinct_targets values(All_Traffic.dest) as targets min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=8089 AND All_Traffic.action="allowed" by All_Traffic.src All_Traffic.dest_port All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | where distinct_targets >= 5 AND NOT cidrmatch("10.0.0.0/8", src) AND NOT cidrmatch("172.16.0.0/12", src) AND NOT cidrmatch("192.168.0.0/16", src) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where LocalPort == 8089
| where ActionType in ("InboundConnectionAccepted", "ConnectionSuccess")
| where RemoteIPType == "Public"
| summarize TargetCount = dcount(DeviceId), AttemptCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Targets = make_set(DeviceName, 50) by RemoteIP
| where TargetCount >= 5 or AttemptCount >= 50
| order by AttemptCount desc
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

`UC_17_6` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
