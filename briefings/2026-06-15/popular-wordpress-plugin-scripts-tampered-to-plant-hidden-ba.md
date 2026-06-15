# [CRIT] Popular WordPress Plugin Scripts Tampered to Plant Hidden Backdoors on Sites

**Source:** The Hacker News
**Published:** 2026-06-15
**Article:** https://thehackernews.com/2026/06/popular-wordpress-plugin-scripts.html

## Threat Profile

Popular WordPress Plugin Scripts Tampered to Plant Hidden Backdoors on Sites 
 Swati Khandelwal  Jun 15, 2026 Web Security / Supply Chain Attack 
An attacker tampered with trusted JavaScript files used by WordPress sites running PushEngage , OptinMonster , and TrustPulse , turning those files into a way to break into the sites.
When a site administrator was logged in as the file loaded, the code created an admin account under the attacker's control and installed a hidden plugin that opened a w…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-10795`
- **IPv4 (defanged):** `84.201.6.54`
- **Domain (defanged):** `tidio.cc`
- **Domain (defanged):** `pushengage.com`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1071.004** — Application Layer Protocol: DNS
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1505.003** — Server Software Component: Web Shell
- **T1195.002** — Supply Chain Compromise: Software Supply Chain
- **T1547.015** — Boot or Logon Autostart: Login Items
- **T1136.002** — Create Account: Domain Account
- **T1098** — Account Manipulation
- **T1189** — Drive-by Compromise
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound connection to tidio.cc exfil/C2 domain or 84.201.6.54

`UC_9_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src_ip) as src_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="84.201.6.54" OR All_Traffic.dest="tidio.cc" OR All_Traffic.url="*tidio.cc*" OR All_Traffic.url="*tidio.cc/cdn-cgi/*") by All_Traffic.dest All_Traffic.dest_ip All_Traffic.url host | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP == "84.201.6.54"
   or RemoteUrl has "tidio.cc"
   or RemoteUrl has "tidio[.]cc"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### DNS resolution for tidio.cc typosquat exfil domain

`UC_9_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where (DNS.query="tidio.cc" OR DNS.query="*.tidio.cc") by DNS.query host | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "DnsQueryResponse"
| extend Query = tostring(parse_json(AdditionalFields).DnsQueryString)
| where Query has "tidio.cc" or Query endswith ".tidio.cc" or Query =~ "tidio.cc"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName,
          Query, AdditionalFields
| order by Timestamp desc
```

### WordPress rogue plugin folder dropped (content-delivery-helper / database-optimizer)

`UC_9_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.action) as action values(Filesystem.process_name) as process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*wp-content/plugins/content-delivery-helper*" OR Filesystem.file_path="*wp-content/plugins/database-optimizer*" OR Filesystem.file_path="*wp-content\\plugins\\content-delivery-helper*" OR Filesystem.file_path="*wp-content\\plugins\\database-optimizer*") by Filesystem.file_path Filesystem.dest host | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"\wp-content\plugins\content-delivery-helper",
                            @"\wp-content\plugins\database-optimizer",
                            "/wp-content/plugins/content-delivery-helper",
                            "/wp-content/plugins/database-optimizer")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Suspicious WordPress admin account created (developer_api1 / dev_xxxxxx)

`UC_9_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Changes.src) as src from datamodel=Change.Account_Management where All_Changes.action=created (All_Changes.user="developer_api1" OR All_Changes.user="dev_*") by All_Changes.user All_Changes.dest | `drop_dm_object_name(All_Changes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Webserver access logs ingested into Defender via custom DCR — adapt to your collector
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("wp user create developer_api1", "developer_api1", "user_login=developer_api1", "user_login=dev_")
   or ProcessCommandLine matches regex @"(?i)\bdev_[a-z0-9]{6,}\b"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Webserver load of tampered Awesome Motive plugin scripts (pushengage-web-sdk.js / pushengage-subscription.js)

`UC_9_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.src) as src from datamodel=Web.Web where Web.url="*clientcdn.pushengage.com*pushengage-web-sdk.js*" OR Web.url="*clientcdn.pushengage.com*pushengage-subscription.js*" earliest="06/12/2026:22:00:00" latest="06/14/2026:23:59:59" by Web.url Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let WindowStart = datetime(2026-06-12T22:00:00Z);
let WindowEnd   = datetime(2026-06-14T23:59:59Z);
DeviceNetworkEvents
| where Timestamp between (WindowStart .. WindowEnd)
| where RemoteUrl has "clientcdn.pushengage.com"
| where RemoteUrl has_any ("pushengage-web-sdk.js", "pushengage-subscription.js")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessAccountName, RemoteUrl, RemoteIP
| order by Timestamp desc
```

### PHP/IIS web process spawns shell or LOLBin from wp-content path

`UC_9_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as child values(Processes.process) as cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name="php-fpm" OR Processes.parent_process_name="php-cgi.exe" OR Processes.parent_process_name="php.exe" OR Processes.parent_process_name="w3wp.exe" OR Processes.parent_process_name="httpd" OR Processes.parent_process_name="nginx") (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="bash" OR Processes.process_name="sh" OR Processes.process_name="wget" OR Processes.process_name="curl.exe" OR Processes.process_name="certutil.exe") (Processes.parent_process="*wp-content*" OR Processes.parent_process="*wp-admin*" OR Processes.process="*wp-content*" OR Processes.process="*wp-admin*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("php-fpm","php-cgi.exe","php.exe","w3wp.exe","httpd","httpd.exe","nginx","nginx.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","wget","curl.exe","curl","certutil.exe","bitsadmin.exe")
   or InitiatingProcessFolderPath has_any ("wp-content","wp-admin")
   or ProcessCommandLine has_any ("wp-content","wp-admin","content-delivery-helper","database-optimizer")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — Popular WordPress Plugin Scripts Tampered to Plant Hidden Backdoors on Sites

`UC_9_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Popular WordPress Plugin Scripts Tampered to Plant Hidden Backdoors on Sites ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pushengage-web-sdk.js","pushengage-subscription.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("pushengage-web-sdk.js","pushengage-subscription.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Popular WordPress Plugin Scripts Tampered to Plant Hidden Backdoors on Sites
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pushengage-web-sdk.js", "pushengage-subscription.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("pushengage-web-sdk.js", "pushengage-subscription.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-10795`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `84.201.6.54`, `tidio.cc`, `pushengage.com`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
