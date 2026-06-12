# [CRIT] Tracking TamperedChef Clusters via Certificate and Code Reuse

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-05-20
**Article:** https://unit42.paloaltonetworks.com/tracking-tampered-chef-clusters/

## Threat Profile

Threat Research Center 
Threat Research 
Malware 
Malware 
Tracking TamperedChef Clusters via Certificate and Code Reuse 
21 min read 
Related Products Cortex Cortex XDR Cortex XSIAM Prisma Browser Prisma SASE Secure Access Service Edge (SASE) Unit 42 Incident Response 
By: Joseph Ganter 
Published: May 20, 2026 
Categories: Malware 
Threat Research 
Tags: Adware 
Appsuite PDF 
Certificates 
CL-CRI-1089 
CL-UNK-1090 
DocuFlex 
EvilAI 
Malvertising 
RATs 
Remote Access Trojan 
TamperedChef 
Execu…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `crystalpdf.com`
- **Domain (defanged):** `vault.appsuites.ai`
- **Domain (defanged):** `pdf-tool.appsuites.ai`
- **Domain (defanged):** `appsuites.ai`
- **Domain (defanged):** `freeonlinetools.info`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1053.005** — Scheduled Task
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1588.003** — Obtain Capabilities: Code Signing Certificates
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1105** — Ingress Tool Transfer
- **T1059** — Command and Scripting Interpreter
- **T1480** — Execution Guardrails
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TamperedChef shell-company code-signing certificate execution (CL-UNK-1090)

`UC_231_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.process_signature_publisher IN ("CANDY TECH LTD","G.R.CIGAR. LTD","G.R.CIGAR LTD","TAU CENTAURI LTD","AMARYLLIS SIGNAL LTD","METROPOLITAN DESIGN LLC") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_signature_publisher | `drop_dm_object_name(Processes)` | where firstTime >= relative_time(now(), "-30d@d")
```

**Defender KQL:**
```kql
let TamperedChefSigners = dynamic(["CANDY TECH LTD","G.R.CIGAR. LTD","G.R.CIGAR LTD","TAU CENTAURI LTD","AMARYLLIS SIGNAL LTD","METROPOLITAN DESIGN LLC"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoCompanyName in~ (TamperedChefSigners)
   or InitiatingProcessVersionInfoCompanyName in~ (TamperedChefSigners)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, SHA256,
          Signer = coalesce(ProcessVersionInfoCompanyName, InitiatingProcessVersionInfoCompanyName),
          Product = ProcessVersionInfoProductName,
          ProcessCommandLine,
          ParentFileName = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### TamperedChef C2 / distribution callback to appsuites.ai and sibling domains

`UC_231_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as resolved from datamodel=Network_Resolution.DNS where (DNS.query="appsuites.ai" OR DNS.query="*.appsuites.ai" OR DNS.query="crystalpdf.com" OR DNS.query="*.crystalpdf.com" OR DNS.query="freeonlinetools.info" OR DNS.query="*.freeonlinetools.info" OR DNS.query="fullpdf.com") by DNS.query DNS.src | `drop_dm_object_name(DNS)` | where firstTime >= relative_time(now(), "-30d@d")
```

**Defender KQL:**
```kql
let TamperedChefHosts = dynamic(["appsuites.ai","pdf-tool.appsuites.ai","vault.appsuites.ai","crystalpdf.com","freeonlinetools.info","fullpdf.com"]);
let NetHits = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where isnotempty(RemoteUrl)
  | extend Host = tolower(tostring(parse_url(RemoteUrl).Host))
  | where Host in~ (TamperedChefHosts) or Host endswith ".appsuites.ai" or Host endswith ".crystalpdf.com"
  | project Timestamp, DeviceName, Source = "Network", Indicator = RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessVersionInfoCompanyName;
let DnsHits = DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | extend Query = tolower(tostring(parse_json(AdditionalFields).DnsQueryString))
  | where Query in~ (TamperedChefHosts) or Query endswith ".appsuites.ai" or Query endswith ".crystalpdf.com"
  | project Timestamp, DeviceName, Source = "DNS", Indicator = Query, RemoteIP = tostring(parse_json(AdditionalFields).IPAddresses), InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessVersionInfoCompanyName;
union NetHits, DnsHits
| order by Timestamp desc
```

### TamperedChef trojanized-app activation via --cm / --enableupdate / --fullupdate flags

`UC_231_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name IN ("AppSuitePDF.exe","CrystalPDF.exe","Calendaromatic.exe","JustAskJacky.exe","PDFEditor.exe","ManualFinder.exe","RecipeLister.exe") OR Processes.process LIKE "%AppSuite%" OR Processes.process LIKE "%CrystalPDF%") AND (Processes.process LIKE "%--cm %" OR Processes.process LIKE "%--cm\"%" OR Processes.process LIKE "%--enableupdate%" OR Processes.process LIKE "%--fullupdate%" OR Processes.process LIKE "%--install %") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | where firstTime >= relative_time(now(), "-30d@d")
```

**Defender KQL:**
```kql
let TamperedChefBinaries = dynamic(["AppSuitePDF.exe","AppSuite.exe","CrystalPDF.exe","Calendaromatic.exe","JustAskJacky.exe","PDFEditor.exe","ManualFinder.exe","RecipeLister.exe","OneStart.exe","EpiBrowser.exe"]);
let TamperedChefSigners = dynamic(["CANDY TECH LTD","G.R.CIGAR. LTD","G.R.CIGAR LTD","TAU CENTAURI LTD","AMARYLLIS SIGNAL LTD","METROPOLITAN DESIGN LLC"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (TamperedChefBinaries)
   or ProcessVersionInfoCompanyName in~ (TamperedChefSigners)
   or ProcessVersionInfoProductName has_any ("AppSuite","CrystalPDF","Calendaromatic","JustAskJacky","Recipe Lister","Manual Finder")
| where ProcessCommandLine has_any ("--cm ","--cm=","--enableupdate","--fullupdate","--install ")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine, SHA256,
          Signer = ProcessVersionInfoCompanyName,
          Product = ProcessVersionInfoProductName,
          ParentFileName = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### TamperedChef scheduled-task persistence via task.xml + obfuscated JS (appsuite-print.js)

`UC_231_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*/create*" Processes.process="*/xml*" (Processes.process LIKE "%\\Temp\\%task.xml%" OR Processes.process LIKE "%\\AppData\\%task.xml%" OR Processes.process LIKE "%AppSuite%task%.xml%" OR Processes.process LIKE "%CrystalPDF%task%.xml%") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | where firstTime >= relative_time(now(), "-30d@d") | join type=outer dest [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") (Processes.process LIKE "%appsuite-print.js%" OR Processes.process LIKE "%appsuite%.js%" OR Processes.process LIKE "%crystalpdf%.js%") by Processes.dest Processes.process | `drop_dm_object_name(Processes)` | rename process as script_cmdline]
```

**Defender KQL:**
```kql
let WindowHours = 24h;
let ScheduleHits = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName =~ "schtasks.exe"
  | where ProcessCommandLine has_all ("/create","/xml")
  | where ProcessCommandLine has_any ("\\Temp\\","\\AppData\\","AppSuite","CrystalPDF","Calendaromatic","JustAskJacky","task.xml")
  | project SchedTime = Timestamp, DeviceName, AccountName,
            SchedCmd = ProcessCommandLine,
            SchedParent = InitiatingProcessFileName,
            SchedParentCompany = InitiatingProcessVersionInfoCompanyName;
let ScriptHits = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName in~ ("wscript.exe","cscript.exe","node.exe")
  | where ProcessCommandLine has_any ("appsuite-print.js","appsuite","crystalpdf","calendaromatic","justaskjacky") and ProcessCommandLine has ".js"
  | project ScriptTime = Timestamp, DeviceName, ScriptCmd = ProcessCommandLine,
            ScriptParent = InitiatingProcessFileName;
ScheduleHits
| join kind=inner ScriptHits on DeviceName
| where ScriptTime between (SchedTime .. SchedTime + WindowHours)
| project SchedTime, ScriptTime, DeviceName, AccountName,
          SchedParent, SchedParentCompany, SchedCmd,
          ScriptParent, ScriptCmd
| order by SchedTime desc
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

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Tracking TamperedChef Clusters via Certificate and Code Reuse

`UC_231_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Tracking TamperedChef Clusters via Certificate and Code Reuse ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("calendaromatic-win_x64.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("calendaromatic-win_x64.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Tracking TamperedChef Clusters via Certificate and Code Reuse
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("calendaromatic-win_x64.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("calendaromatic-win_x64.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `crystalpdf.com`, `vault.appsuites.ai`, `pdf-tool.appsuites.ai`, `appsuites.ai`, `freeonlinetools.info`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
