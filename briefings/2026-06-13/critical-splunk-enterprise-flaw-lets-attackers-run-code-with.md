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
- **T1505.003** — Server Software Component: Web Shell
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071** — Application Layer Protocol
- **T1105** — Ingress Tool Transfer
- **T1518.001** — Software Discovery: Security Software Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated request to Splunk PostgreSQL sidecar /v1/postgres/recovery/{backup,restore} (CVE-2026-20253)

`UC_4_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as methods values(Web.status) as statuses values(Web.user_agent) as user_agents from datamodel=Web where (Web.url="*/v1/postgres/recovery/backup*" OR Web.url="*/v1/postgres/recovery/restore*") by Web.src, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| where NOT (cidrmatch("127.0.0.0/8", src) OR cidrmatch("::1/128", src))
| eval is_vuln_probe=if(match(mvjoin(statuses,","),"400"),"likely-vulnerable",if(match(mvjoin(statuses,","),"401"),"likely-patched","unknown"))
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Defender for Endpoint on Linux does not capture HTTP URIs for non-IIS servers.
// Best-effort: surface external sources establishing TCP to Splunk hosts on the
// management-tier listener (port 8089 is splunkd; sidecar port may differ — confirm in your env).
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where LocalPort in (8089, 8000)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName has_any ("splunkd","postgres")
| project Timestamp, DeviceName, RemoteIP, RemotePort, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine
| summarize ConnCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, RemoteIP, LocalPort, InitiatingProcessFileName
| order by FirstSeen desc
```

### Write to Splunk PostgreSQL .pgpass or modular-input .py file under /opt/splunk (CVE-2026-20253 file-write primitive)

`UC_4_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as actions values(Filesystem.process_name) as writers values(Filesystem.process_path) as writer_paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/opt/splunk/var/packages/data/postgres/.pgpass" OR Filesystem.file_path="/opt/splunk/etc/apps/splunk_secure_gateway/bin/ssg_enable_modular_input.py" OR (Filesystem.file_path="/opt/splunk/etc/apps/*/bin/*.py" AND Filesystem.action IN ("created","modified","renamed"))) by Filesystem.dest, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
| where NOT match(writers,"(?i)^(apt|dpkg|rpm|yum|dnf|tar|cp|splunk-install|splunk\\.upgrade)$")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "/opt/splunk/var/packages/data/postgres/" and FileName =~ ".pgpass")
   or (FolderPath has "/opt/splunk/etc/apps/splunk_secure_gateway/bin/" and FileName =~ "ssg_enable_modular_input.py")
   or (FolderPath matches regex @"/opt/splunk/etc/apps/[^/]+/bin/" and FileName endswith ".py")
| where InitiatingProcessFileName !in~ ("dpkg","rpm","apt","yum","dnf","tar","cp","mv")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          WriterParent = InitiatingProcessParentFileName,
          AccountName = InitiatingProcessAccountName
| order by Timestamp desc
```

### splunkd or postgres process spawning shell/interpreter (CVE-2026-20253 RCE execution)

`UC_4_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.user) as users from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("splunkd","postgres","python","python3") AND Processes.process_name IN ("bash","sh","dash","ash","zsh","nc","ncat","curl","wget","perl","ruby","socat") AND (Processes.parent_process_path="/opt/splunk/*" OR Processes.process_path="/tmp/*" OR Processes.process="*ssg_enable_modular_input*") by Processes.dest, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| where NOT match(cmdlines,"(?i)splunk-launch|splunk\\.sh|btool|splunk\\s+status")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("splunkd","postgres","python","python3")
| where InitiatingProcessFolderPath has "/opt/splunk/"
| where FileName in~ ("bash","sh","dash","ash","zsh","nc","ncat","curl","wget","perl","ruby","socat","python","python3")
| where ProcessCommandLine !has "splunk-launch.conf"
  and ProcessCommandLine !has "btool"
  and InitiatingProcessCommandLine !has "splunk status"
| extend SuspectModInput = iff(InitiatingProcessCommandLine has "ssg_enable_modular_input", "YES", "")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SuspectModInput
| order by Timestamp desc
```

### Splunk host outbound PostgreSQL connection to non-RFC1918 host (attacker-DB pull via CVE-2026-20253 /backup)

`UC_4_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ips values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.app) as apps from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=5432 AND All_Traffic.src_category="splunk_server" AND NOT (All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=172.16.0.0/12 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip=127.0.0.0/8) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemotePort == 5432
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("postgres","splunkd","pg_dump","psql")
  or InitiatingProcessFolderPath has "/opt/splunk/"
| project Timestamp, DeviceName, RemoteIP, RemotePort,
          Initiator = InitiatingProcessFileName,
          InitiatorPath = InitiatingProcessFolderPath,
          InitiatorCmd = InitiatingProcessCommandLine,
          ParentFile = InitiatingProcessParentFileName
| summarize ConnCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SampleCmd=any(InitiatorCmd) by DeviceName, RemoteIP, Initiator, InitiatorPath
| order by FirstSeen desc
```

### Inventory of Splunk Enterprise versions vulnerable to CVE-2026-20253

`UC_4_11` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| inputlookup splunk_host_inventory.csv
| where like(software_name, "Splunk Enterprise%")
| eval ver_parts=split(version,".")
| eval major=tonumber(mvindex(ver_parts,0))
| eval minor=tonumber(mvindex(ver_parts,1))
| eval patch=tonumber(mvindex(ver_parts,2))
| eval vuln_status=case(
    major==10 AND minor==0 AND patch<7, "VULNERABLE — upgrade to 10.0.7",
    major==10 AND minor==2 AND patch<4, "VULNERABLE — upgrade to 10.2.4",
    major==10 AND minor==4, "NOT AFFECTED (10.4 branch)",
    1==1, "check manually"
  )
| where vuln_status LIKE "VULNERABLE%"
| table host, version, vuln_status, last_seen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor =~ "splunk" and SoftwareName has "enterprise"
| extend parts = split(SoftwareVersion, ".")
| extend major = toint(parts[0]), minor = toint(parts[1]), patch = toint(parts[2])
| extend VulnStatus = case(
    major == 10 and minor == 0 and patch < 7, "VULNERABLE — upgrade to 10.0.7",
    major == 10 and minor == 2 and patch < 4, "VULNERABLE — upgrade to 10.2.4",
    major == 10 and minor == 4, "NOT AFFECTED",
    "review")
| where VulnStatus startswith "VULNERABLE"
| project DeviceName, OSPlatform, SoftwareName, SoftwareVersion, VulnStatus, Timestamp
| order by DeviceName asc
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

`UC_4_6` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
