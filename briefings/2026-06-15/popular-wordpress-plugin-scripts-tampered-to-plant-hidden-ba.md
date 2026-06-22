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
- **T1567.002** — Exfiltration Over Web Service
- **T1505.003** — Server Software Component: Web Shell
- **T1136** — Create Account
- **T1078** — Valid Accounts
- **T1059** — Command and Scripting Interpreter
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Rogue admin & self-hiding plugin C2/exfil to tidio.cc and 84.201.6.54

`UC_141_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="84.201.6.54" by _time, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query="*tidio.cc*" by _time, DNS.src, DNS.query | `drop_dm_object_name(DNS)`] | sort - _time
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "tidio.cc" or RemoteIP == "84.201.6.54"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Hidden WordPress backdoor plugin dropped (content-delivery-helper / database-optimizer)

`UC_141_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*content-delivery-helper*" OR Filesystem.file_path="*database-optimizer*") by _time, Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.action | `drop_dm_object_name(Filesystem)` | sort - _time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath contains "content-delivery-helper" or FolderPath contains "database-optimizer"
| where FolderPath contains "wp-content"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Rogue WordPress administrator account (developer_api1 / dev_xxxxxx)

`UC_141_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process="*developer_api1*" OR Processes.process="*dev_*") (Processes.process="*user create*" OR Processes.process="*wp_users*" OR Processes.process="*role=administrator*" OR Processes.process="*INSERT INTO*") by _time, Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - _time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "developer_api1" or ProcessCommandLine matches regex @"(?i)dev_[a-z0-9]{6}"
| where ProcessCommandLine has_any ("user create","wp user","wp_users","INSERT INTO","role=administrator","role administrator")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Web server PHP runtime spawning a shell (WordPress web shell execution)

`UC_141_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("php.exe","php-cgi.exe","php-fpm","httpd","apache2","nginx","w3wp.exe")) (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","wscript.exe","cscript.exe")) by _time, Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - _time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm","php-fpm8.1","php-fpm8.2","php-fpm8.3","httpd","apache2","nginx","w3wp.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, ParentProc = InitiatingProcessFileName, ParentPath = InitiatingProcessFolderPath, Child = FileName, ChildCmd = ProcessCommandLine
| order by Timestamp desc
```

### WordPress plugin/theme PHP files modified by the web runtime (backdoor / skimmer injection)

`UC_141_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_path="*wp-content*" Filesystem.file_name="*.php" by _time, Filesystem.dest, Filesystem.file_path, Filesystem.file_name, Filesystem.action | `drop_dm_object_name(Filesystem)` | stats count, min(_time) as firstSeen, max(_time) as lastSeen, values(file_path) as paths by dest | sort - count
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileModified","FileCreated","FileRenamed")
| where FolderPath has_any ("wp-content","wp-includes","wp-admin")
| where FileName endswith ".php"
| where InitiatingProcessFileName has_any ("php","php-cgi","php-fpm","httpd","apache2","nginx","w3wp.exe")
| summarize Writes = count(), Files = make_set(FolderPath, 50), First = min(Timestamp), Last = max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Last desc
```

### Admin browser loaded poisoned PushEngage CDN script during exposure window

`UC_141_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where Web.url="*clientcdn.pushengage.com*" (Web.url="*pushengage-web-sdk.js*" OR Web.url="*pushengage-subscription.js*") by _time, Web.src, Web.user, Web.url, Web.dest, Web.http_user_agent | `drop_dm_object_name(Web)` | where _time>=strptime("2026-06-12T00:00:00","%Y-%m-%dT%H:%M:%S") AND _time<=strptime("2026-06-14T23:59:59","%Y-%m-%dT%H:%M:%S") | sort _time
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-06-12T00:00:00Z) .. datetime(2026-06-14T23:59:59Z))
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe")
| where RemoteUrl has "clientcdn.pushengage.com"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Timestamp asc
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

`UC_141_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
