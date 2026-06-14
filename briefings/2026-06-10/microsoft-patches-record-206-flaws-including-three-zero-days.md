# [CRIT] Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE Bugs

**Source:** The Hacker News
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
- **T1588.006** — Obtain Capabilities: Vulnerabilities
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1112** — Modify Registry
- **T1059** — Command and Scripting Interpreter
- **T1203** — Exploitation for Client Execution
- **T1505.003** — Server Software Component: Web Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1068** — Exploitation for Privilege Escalation
- **T1588.005** — Obtain Capabilities: Exploits

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unpatched June 2026 Patch Tuesday CVE inventory (kernel TCP/IP, DHCP, HTTP.sys, BitLocker)

`UC_66_7` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-45657","CVE-2026-47291","CVE-2026-44815","CVE-2026-45585","CVE-2026-45655","CVE-2026-45658","CVE-2026-50507","CVE-2026-45586","CVE-2026-49160","CVE-2026-8863","CVE-2025-10263") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | sort 0 - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2026-45657","CVE-2026-47291","CVE-2026-44815","CVE-2026-45585","CVE-2026-45655","CVE-2026-45658","CVE-2026-50507","CVE-2026-45586","CVE-2026-49160","CVE-2026-8863","CVE-2025-10263")
| join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
| summarize ExposedDevices = dcount(DeviceId),
            SampleDevices  = make_set(DeviceName, 25),
            FirstSeen      = min(Timestamp),
            MaxCvss        = max(CvssScore),
            ExploitAvailable = max(tostring(IsExploitAvailable))
            by CveId, SoftwareName, RecommendedSecurityUpdate, VulnerabilitySeverityLevel
| order by MaxCvss desc, ExposedDevices desc
```

### HTTP/2 Bomb mitigation tampering — MaxHeadersCount registry value (CVE-2026-49160)

`UC_66_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as value_data values(Registry.registry_previous_value_data) as previous_value_data values(Registry.process_name) as process_name values(Registry.user) as user from datamodel=Endpoint.Registry where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters*" Registry.registry_value_name="MaxHeadersCount" Registry.action IN ("modified","deleted","created") by Registry.dest Registry.registry_path Registry.registry_value_name Registry.action | `drop_dm_object_name(Registry)` | where action!="created" OR (action="created" AND value_data IN ("0","0x0"))
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
| where RegistryValueName =~ "MaxHeadersCount"
| where ActionType in~ ("RegistryValueSet","RegistryValueDeleted","RegistryKeyDeleted")
| extend NewVal = tostring(RegistryValueData), PrevVal = tostring(PreviousRegistryValueData)
| where ActionType != "RegistryValueSet" or NewVal in ("0","0x0","") or toint(NewVal) < toint(coalesce(PrevVal,"0"))
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, NewVal, PrevVal,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### DHCP Client svchost anomalous child process (CVE-2026-44815 post-exploit)

`UC_66_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.process_integrity_level) as integrity from datamodel=Endpoint.Processes where Processes.parent_process_name="svchost.exe" Processes.parent_process IN ("*-k LocalServiceNetworkRestricted*","*-s Dhcp*","*-s dhcp*") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","net.exe","whoami.exe","nltest.exe","ipconfig.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has_any ("-s Dhcp", "-s dhcp", "LocalServiceNetworkRestricted")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","net.exe","net1.exe","whoami.exe","nltest.exe","ipconfig.exe","hostname.exe")
| project Timestamp, DeviceName, AccountName, AccountDomain,
          ParentImage=InitiatingProcessFolderPath,
          ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath,
          ChildCmd=ProcessCommandLine,
          ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### HTTP.sys / IIS w3wp.exe spawning shell or LOLBin (CVE-2026-47291 post-exploit)

`UC_66_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user values(Processes.process_integrity_level) as integrity from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","net.exe","net1.exe","whoami.exe","nltest.exe","systeminfo.exe","tasklist.exe") by Processes.dest Processes.process_name Processes.parent_process Processes.user | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","net.exe","net1.exe","whoami.exe","nltest.exe","systeminfo.exe","tasklist.exe","ipconfig.exe","hostname.exe")
| project Timestamp, DeviceName, AccountName, AccountDomain,
          ParentCmd=InitiatingProcessCommandLine,
          ParentIntegrity=InitiatingProcessIntegrityLevel,
          ChildImage=FolderPath,
          ChildCmd=ProcessCommandLine,
          ChildIntegrity=ProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### CTFMON spawning elevated child or CTFMON-hosted privilege escalation (CVE-2026-45586 / GreenPlasma)

`UC_66_11` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_integrity_level) as child_integrity values(Processes.parent_process_integrity_level) as parent_integrity from datamodel=Endpoint.Processes where Processes.parent_process_name="ctfmon.exe" Processes.process_integrity_level IN ("high","system") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where parent_integrity!="high" AND parent_integrity!="system"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "ctfmon.exe"
| where FileName !in~ ("ctfmon.exe","conhost.exe","wermgr.exe","WerFault.exe")
| where ProcessIntegrityLevel in~ ("High","System")
| where InitiatingProcessIntegrityLevel !in~ ("High","System")
| project Timestamp, DeviceName, AccountName, AccountDomain,
          ParentImage=InitiatingProcessFolderPath,
          ParentIntegrity=InitiatingProcessIntegrityLevel,
          ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath,
          ChildIntegrity=ProcessIntegrityLevel,
          ChildCmd=ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### PoC artefact drop — Chaotic Eclipse named exploits (YellowKey, GreenPlasma, MiniPlasma, RoguePlanet, bitskrieg)

`UC_66_12` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("*YellowKey*","*yellowkey*","*GreenPlasma*","*greenplasma*","*MiniPlasma*","*miniplasma*","*RoguePlanet*","*rogueplanet*","*bitskrieg*","*BitSkrieg*") OR Filesystem.file_path IN ("*YellowKey*","*GreenPlasma*","*MiniPlasma*","*RoguePlanet*","*bitskrieg*")) by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let Codenames = dynamic(["yellowkey","greenplasma","miniplasma","rogueplanet","bitskrieg"]);
let FileHits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in~ ("FileCreated","FileRenamed","FileModified")
    | extend low_name = tolower(FileName), low_path = tolower(FolderPath)
    | where low_name has_any (Codenames) or low_path has_any (Codenames)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
let ProcHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | extend low_cmd = tolower(ProcessCommandLine), low_img = tolower(FolderPath), low_name = tolower(FileName)
    | where low_name has_any (Codenames) or low_img has_any (Codenames) or low_cmd has_any (Codenames)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine;
union FileHits, ProcHits
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

### Article-specific behavioural hunt — Microsoft Patches Record 206 Flaws, Including Three Zero-Days and Critical RCE B

`UC_66_6` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
