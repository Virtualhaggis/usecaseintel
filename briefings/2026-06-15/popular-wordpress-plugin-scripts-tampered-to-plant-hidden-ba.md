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
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1189** — Drive-by Compromise
- **T1136.001** — Create Account: Local Account
- **T1098** — Account Manipulation
- **T1505.003** — Server Software Component: Web Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound traffic to tidio.cc or 84.201.6.54 (Awesome Motive supply-chain C2)

`UC_13_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where All_Traffic.dest_ip="84.201.6.54" OR All_Traffic.dest="tidio.cc" OR All_Traffic.dest="*.tidio.cc" by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=true count from datamodel=Network_Resolution where Network_Resolution.DNS.query="tidio.cc" OR Network_Resolution.DNS.query="*.tidio.cc" by Network_Resolution.DNS.src Network_Resolution.DNS.query | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2Domains = dynamic(["tidio.cc"]);
let C2IPs = dynamic(["84.201.6.54"]);
DeviceNetworkEvents
| where Timestamp between (datetime(2026-06-12T00:00:00Z) .. datetime(2026-06-21T00:00:00Z))
| where RemoteIP in (C2IPs)
   or RemoteUrl has_any (C2Domains)
   or RemoteUrl matches regex @"(?i)tidio\.cc(/|$)"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Tampered PushEngage SDK fetched from clientcdn.pushengage.com during exposure window

`UC_13_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user from datamodel=Web where (Web.url="*pushengage-web-sdk.js*" OR Web.url="*pushengage-subscription.js*") AND Web.url="*clientcdn.pushengage.com*" AND _time>=1749686400 AND _time<=1749945600 by Web.src Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-06-12T00:00:00Z) .. datetime(2026-06-14T23:59:59Z))
| where RemoteUrl has "clientcdn.pushengage.com"
| where RemoteUrl has_any ("pushengage-web-sdk.js", "pushengage-subscription.js")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Rogue WordPress admin account created matching developer_api1 / dev_xxxxxx

`UC_13_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Changes.src) as src values(All_Changes.action) as action from datamodel=Change where All_Changes.object_category="user" AND (All_Changes.user="developer_api1" OR All_Changes.user="dev_*") by All_Changes.dest All_Changes.user | `drop_dm_object_name(All_Changes)` | append [ | tstats summariesonly=true count from datamodel=Web where (Web.url="*wp-admin/user-new.php*" OR Web.url="*wp-json/wp/v2/users*") AND (Web.url="*developer_api1*" OR Web.url="*dev_*") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\wp-content\" or FolderPath has "/wp-content/"
| where InitiatingProcessCommandLine has_any ("developer_api1", "dev_")),
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("developer_api1", "INSERT INTO wp_users", "wp_insert_user")
  and ProcessCommandLine matches regex @"(?i)dev_[a-z0-9]{4,8}")
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Suspicious WordPress plugin folder created (content-delivery-helper / database-optimizer)

`UC_13_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/wp-content/plugins/content-delivery-helper/*" OR Filesystem.file_path="*/wp-content/plugins/database-optimizer/*" OR Filesystem.file_path="*\\wp-content\\plugins\\content-delivery-helper\\*" OR Filesystem.file_path="*\\wp-content\\plugins\\database-optimizer\\*") by Filesystem.dest Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where FolderPath matches regex @"(?i)[\\/]wp-content[\\/]plugins[\\/](content-delivery-helper|database-optimizer)[\\/]"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### WordPress PHP process spawning shell from wp-content directory

`UC_13_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php.exe","php-cgi.exe","php-fpm","php")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","nc","ncat","curl","wget")) by Processes.dest Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm","php")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","nc","ncat","curl.exe","wget.exe")
   or ProcessCommandLine has_any ("base64 -d", "FromBase64String", "eval(", "system(", "passthru(")
| where InitiatingProcessFolderPath has_any ("wp-content","wp-admin","wp-includes")
   or InitiatingProcessCommandLine has_any ("wp-content","wp-admin")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine, SHA256
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

`UC_13_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
