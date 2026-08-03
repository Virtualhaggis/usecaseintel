# [CRIT] Critical TeamCity Flaw Could Let Attackers Run OS Commands Without Logging In

**Source:** The Hacker News
**Published:** 2026-07-28
**Article:** https://thehackernews.com/2026/07/critical-teamcity-flaw-could-let.html

## Threat Profile

Critical TeamCity Flaw Could Let Attackers Run OS Commands Without Logging In 
 Ravie Lakshmanan  Jul 28, 2026 Vulnerability / Enterprise Security 
JetBrains is urging customers of on-premise versions of TeamCity to update to the latest version following the discovery of a critical security issue that could result in arbitrary code execution.
The vulnerability, assigned CVE-2026-63077 (CVSS score: 9.8), affects all TeamCity On-Premises versions. It has been addressed in versions 2025.11.7 and …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-63077`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1505.003** — Server Software Component: Web Shell
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Internet-exposed TeamCity On-Premises receiving external requests to REST/login surface (CVE-2026-63077)

`UC_101_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url IN ("*/app/rest*","*/app/agents*","*/RPC2*","*/login.html*","*/guestLogin.html*") OR Web.dest_port=8111) by Web.src Web.dest Web.dest_port Web.url Web.status Web.http_user_agent Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("192.168.0.0/16",src) AND NOT cidrmatch("172.16.0.0/12",src)
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 8111 or (InitiatingProcessFolderPath has "TeamCity" and LocalPort in (80, 443, 8111))
| where RemoteIPType == "Public"
| summarize Conns = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Ports = make_set(LocalPort, 10) by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Conns desc
```

### Vulnerable JetBrains TeamCity On-Premises version exposed (CVE-2026-63077)

`UC_101_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-63077" by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-63077"
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### TeamCity server process spawning OS command interpreter (CVE-2026-63077 RCE)

`UC_101_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh","bash","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","curl.exe","wget.exe") (Processes.parent_process_path="*TeamCity*" OR Processes.parent_process_name IN ("TeamCity.exe","TeamCityService.exe","teamcityd")) Processes.parent_process_path!="*buildAgent*" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_path Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe", "TeamCity.exe", "TeamCityService.exe", "teamcityd")
| where InitiatingProcessFolderPath has "TeamCity" or InitiatingProcessCommandLine has_any ("jetbrains.buildServer", "teamcity-server", "bootstrap.jar", "Dteamcity")
| where InitiatingProcessFolderPath !has "buildAgent" and InitiatingProcessCommandLine !has "buildAgent"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh", "dash", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")
| project Timestamp, DeviceName, AccountName, ParentImage = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine, Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### TeamCity server writing webshell or script/executable to webapps/data dirs (CVE-2026-63077 payload drop)

`UC_101_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where ((Filesystem.file_path="*TeamCity*webapps*" AND Filesystem.file_name IN ("*.jsp","*.jspx","*.jspf","*.war","*.aspx")) OR (Filesystem.file_path="*TeamCity*" AND Filesystem.file_name IN ("*.ps1","*.bat","*.cmd","*.sh","*.vbs","*.hta"))) Filesystem.file_path!="*buildAgent*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe", "TeamCity.exe", "TeamCityService.exe", "teamcityd")
| where InitiatingProcessFolderPath has "TeamCity" or InitiatingProcessCommandLine has_any ("jetbrains.buildServer", "teamcity-server", "bootstrap.jar")
| where InitiatingProcessFolderPath !has "buildAgent"
| where (FolderPath has "webapps" and FileName matches regex @"(?i)\.(jsp|jspx|jspf|war|aspx|asp)$")
     or FileName matches regex @"(?i)\.(ps1|bat|cmd|sh|vbs|hta)$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Outbound C2/reverse-shell egress from TeamCity server process (CVE-2026-63077 post-exploit)

`UC_101_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("java.exe","TeamCity.exe","TeamCityService.exe") All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("10.0.0.0/8",dest) AND NOT cidrmatch("192.168.0.0/16",dest) AND NOT cidrmatch("172.16.0.0/12",dest)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe", "TeamCity.exe", "TeamCityService.exe", "teamcityd")
| where InitiatingProcessFolderPath has "TeamCity" or InitiatingProcessCommandLine has_any ("jetbrains.buildServer", "teamcity-server", "bootstrap.jar")
| where InitiatingProcessFolderPath !has "buildAgent"
| where RemoteIPType == "Public"
| where isempty(RemoteUrl) or RemoteUrl !endswith "jetbrains.com"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Conns = count(), Ports = make_set(RemotePort, 20) by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| order by FirstSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-63077`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
