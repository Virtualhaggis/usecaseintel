# [CRIT] Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE Bugs

**Source:** The Hacker News, BleepingComputer
**Published:** 2026-06-10
**Article:** https://thehackernews.com/2026/06/microsoft-patches-record-206-flaws.html

## Threat Profile

Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE Bugs 
 Ravie Lakshmanan  Jun 10, 2026 Vulnerability / Zero-Day 
Microsoft on Tuesday released fixes for a record 206 security vulnerabilities impacting its software portfolio, including three flaws that have been publicly disclosed at the time of release.
Of the 206 flaws, 39 are rated Critical, and 167 are rated Important in severity. This includes 63 privilege escalation, 56 remote code execution, 30 information d…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-10263`
- **CVE:** `CVE-2026-8863`
- **CVE:** `CVE-2026-45657`
- **CVE:** `CVE-2026-47291`
- **CVE:** `CVE-2026-44815`
- **CVE:** `CVE-2026-45585`
- **CVE:** `CVE-2026-45655`
- **CVE:** `CVE-2026-45658`
- **CVE:** `CVE-2026-50507`
- **CVE:** `CVE-2026-45586`
- **CVE:** `CVE-2026-49160`
- **CVE:** `CVE-2020-17103`

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
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
- **T1499.002** — Endpoint Denial of Service: Service Exhaustion Flood
- **T1203** — Exploitation for Client Execution
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### RoguePlanet Defender race condition - MsMpEng.exe spawns SYSTEM shell

`UC_22_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.user) as user values(Processes.process_integrity_level) as integrity_level from datamodel=Endpoint.Processes where Processes.parent_process_name="MsMpEng.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wmic.exe","wscript.exe","cscript.exe") by Processes.dest Processes.parent_process_name Processes.process_name Processes.process_id _time span=1m | `drop_dm_object_name(Processes)` | where match(user,"(?i)SYSTEM") OR match(integrity_level,"(?i)System") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where FileName has_any ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wmic.exe","wscript.exe","cscript.exe")
| where AccountName =~ "system" or ProcessIntegrityLevel =~ "System"
| project Timestamp, DeviceName, AccountName,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildFile  = FileName,
          ChildCmd   = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### CTFMON privilege escalation (GreenPlasma / CVE-2026-45586) - ctfmon.exe spawning shells or elevated

`UC_22_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.process_integrity_level) as integrity_level from datamodel=Endpoint.Processes where (Processes.parent_process_name="ctfmon.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe")) OR (Processes.process_name="ctfmon.exe" Processes.process_integrity_level IN ("high","system")) by Processes.dest Processes.parent_process_name Processes.process_name Processes.process_id _time span=1m | `drop_dm_object_name(Processes)` | where NOT match(user,"^.*\$$") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let CtfmonAsParent = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "ctfmon.exe"
    | where FileName has_any ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe")
    | project Timestamp, DeviceName, AccountName,
              Signal = "CtfmonSpawnedShell",
              ParentCmd = InitiatingProcessCommandLine,
              ChildFile = FileName,
              ChildCmd = ProcessCommandLine,
              ParentIntegrity = InitiatingProcessIntegrityLevel,
              ChildIntegrity = ProcessIntegrityLevel;
let CtfmonElevated = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "ctfmon.exe"
    | where ProcessIntegrityLevel in ("High","System")
    | where AccountName !endswith "$" and AccountName !in~ ("system","local service","network service")
    | project Timestamp, DeviceName, AccountName,
              Signal = "CtfmonElevatedIntegrity",
              ParentCmd = InitiatingProcessCommandLine,
              ChildFile = FileName,
              ChildCmd = ProcessCommandLine,
              ParentIntegrity = InitiatingProcessIntegrityLevel,
              ChildIntegrity = ProcessIntegrityLevel;
union CtfmonAsParent, CtfmonElevated
| order by Timestamp desc
```

### HTTP/2 Bomb DoS against IIS (CVE-2026-49160) - rapid w3wp.exe churn and HTTP.sys errors

`UC_22_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as request_count, dc(Web.src) as src_count, max(Web.response_time) as max_resp, sum(eval(if(Web.status>=500,1,0))) as error_5xx from datamodel=Web.Web where Web.app="IIS" by Web.dest, _time span=1m | `drop_dm_object_name(Web)` | where request_count > 500 AND (error_5xx > 50 OR max_resp > 30000) | join type=inner dest [ | tstats `summariesonly` count as w3wp_starts from datamodel=Endpoint.Processes where Processes.process_name="w3wp.exe" by Processes.dest, _time span=5m | `drop_dm_object_name(Processes)` | where w3wp_starts > 3 | rename Processes.dest as dest ]
```

**Defender KQL:**
```kql
let WindowMin = 5m;
let WorkerChurn = DeviceProcessEvents
    | where Timestamp > ago(1h)
    | where FileName =~ "w3wp.exe"
    | summarize StartCount = count(), AnyCmd = any(ProcessCommandLine) by bin(Timestamp, WindowMin), DeviceName
    | where StartCount >= 4;
let PoolCrash = DeviceEvents
    | where Timestamp > ago(1h)
    | where ActionType has_any ("AppPoolRecycle","ProcessCrash")
    | where FileName =~ "w3wp.exe" or InitiatingProcessFileName =~ "w3wp.exe"
    | summarize CrashCount = count() by bin(Timestamp, WindowMin), DeviceName;
WorkerChurn
| join kind=leftouter PoolCrash on DeviceName, $left.Timestamp == $right.Timestamp
| project Timestamp, DeviceName, StartCount, CrashCount, SampleCmd = AnyCmd
| order by Timestamp desc
```

### SYSTEM-level shell from network-service host (CVE-2026-45657 / 47291 / 44815 post-RCE)

`UC_22_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("svchost.exe","w3wp.exe") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe") by Processes.dest Processes.parent_process_name Processes.process_name Processes.process_id _time span=1m | `drop_dm_object_name(Processes)` | where match(user,"(?i)SYSTEM") | where (parent_process_name="svchost.exe" AND match(parent_cmd,"(?i)(Dhcp|tcpip|http)")) OR parent_process_name="w3wp.exe"
```

**Defender KQL:**
```kql
let SuspiciousChildren = dynamic(["cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe"]);
let Candidates = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("svchost.exe","w3wp.exe")
    | where FileName has_any (SuspiciousChildren)
    | where AccountSid =~ "S-1-5-18" or AccountName =~ "system"
    | where (InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has_any ("Dhcp","dhcp","DHCP","tcpip","Tcpip","TcpIp","http")) or InitiatingProcessFileName =~ "w3wp.exe";
let PriorLogon = DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where LogonType in (2, 10, 7)
    | summarize InteractiveLogons = count() by DeviceName, bin(Timestamp, 10m);
Candidates
| join kind=leftouter PriorLogon on DeviceName, $left.Timestamp == $right.Timestamp
| where isnull(InteractiveLogons) or InteractiveLogons == 0
| project Timestamp, DeviceName, AccountName,
          ParentFile = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildFile  = FileName,
          ChildCmd   = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel
| order by Timestamp desc
```

### Patch compliance hunt - June 2026 critical zero-day and network-RCE CVEs

`UC_22_11` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Vulnerabilities.severity) as severity values(Vulnerabilities.signature) as recommendation from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-45657","CVE-2026-47291","CVE-2026-44815","CVE-2026-45585","CVE-2026-50507","CVE-2026-45586","CVE-2026-49160","CVE-2026-45655","CVE-2026-45658","CVE-2026-8863","CVE-2025-10263") by Vulnerabilities.dest Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | sort - severity dest
```

**Defender KQL:**
```kql
let CriticalCVEs = dynamic(["CVE-2026-45657","CVE-2026-47291","CVE-2026-44815","CVE-2026-45585","CVE-2026-50507","CVE-2026-45586","CVE-2026-49160","CVE-2026-45655","CVE-2026-45658","CVE-2026-8863","CVE-2025-10263"]);
let ExposureSet = DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, OSVersion, MachineGroup) by DeviceId, DeviceName;
DeviceTvmSoftwareVulnerabilities
| where CveId in (CriticalCVEs)
| join kind=leftouter ExposureSet on DeviceId
| extend Priority = case(
    IsInternetFacing == true and CveId in ("CVE-2026-45657","CVE-2026-47291","CVE-2026-44815","CVE-2026-49160"), "P1-InternetFacingRCE",
    CveId in ("CVE-2026-45657","CVE-2026-47291","CVE-2026-44815"), "P2-UnauthRCE",
    CveId in ("CVE-2026-50507","CVE-2026-49160","CVE-2026-45586"), "P3-PublicZeroDay",
    "P4")
| project DeviceName, OSPlatform, OSVersion, IsInternetFacing, MachineGroup, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, Priority
| order by Priority asc, DeviceName asc
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

### Article-specific behavioural hunt — Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE B

`UC_22_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE B ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("http.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("http.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE B
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-10263`, `CVE-2026-8863`, `CVE-2026-45657`, `CVE-2026-47291`, `CVE-2026-44815`, `CVE-2026-45585`, `CVE-2026-45655`, `CVE-2026-45658` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
