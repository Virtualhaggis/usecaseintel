# [HIGH] OptinMonster WordPress plugin hacked in CDN supply-chain attack

**Source:** BleepingComputer
**Published:** 2026-06-15
**Article:** https://www.bleepingcomputer.com/news/security/optinmonster-wordpress-plugin-hacked-in-cdn-supply-chain-attack/

## Threat Profile

OptinMonster WordPress plugin hacked in CDN supply-chain attack 
By Bill Toulas 
June 15, 2026
01:37 PM
0 


WordPress plugins OptinMonster, TrustPulse, and PushEngage have been compromised in a supply-chain attack impacting Awesome Motive's content distribution network (CDN).


Of the three products, the OptinMonster lead-generation and conversion optimization platform is the most popular, with at least 1.2 million websites using it.


E-commerce security firm Sansec discovered the attack…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `84.201.6.54`
- **Domain (defanged):** `tidio.cc`
- **Domain (defanged):** `a.omappapi.com`
- **Domain (defanged):** `a.opmnstr.com`
- **Domain (defanged):** `a.optnmstr.com`
- **Domain (defanged):** `a.trstplse.com`
- **Domain (defanged):** `clientcdn.pushengage.com`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1189** — Drive-by Compromise
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1102** — Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1136.001** — Create Account: Local Account
- **T1078.003** — Valid Accounts: Local Accounts
- **T1098** — Account Manipulation
- **T1505.003** — Server Software Component: Web Shell
- **T1554** — Compromise Host Software Binary
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Admin browser fetched malicious api.min.js from Awesome Motive CDN during incident window

`UC_0_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.dest IN ("a.omappapi.com","a.opmnstr.com","a.optnmstr.com","a.trstplse.com","clientcdn.pushengage.com")) AND Web.url="*api.min.js*" earliest=06/12/2026:22:17:00 latest=06/13/2026:19:02:00 by Web.src, Web.user, Web.dest, Web.url, Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-06-12T22:17:00Z) .. datetime(2026-06-13T19:02:00Z))
| where RemoteUrl has_any ("a.omappapi.com","a.opmnstr.com","a.optnmstr.com","a.trstplse.com","clientcdn.pushengage.com")
| where RemoteUrl has "api.min.js"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by Timestamp asc
```

### WordPress backdoor C2 to tidio.cc typosquat / 84.201.6.54

`UC_0_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic where (All_Traffic.dest_host="*tidio.cc" OR All_Traffic.dest="84.201.6.54") AND NOT All_Traffic.dest_host="*.tidio.com" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_host, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Network_Resolution where DNS.query="*tidio.cc" by DNS.src, DNS.query, DNS.answer | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let suspicious_dns = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("DnsConnectionInspected","ConnectionSuccess","ConnectionRequest")
    | where RemoteUrl endswith "tidio.cc" or RemoteUrl == "tidio.cc"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, ActionType;
let ip_hits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP == "84.201.6.54"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, ActionType;
union suspicious_dns, ip_hits
| order by Timestamp desc
```

### Rogue WordPress administrator account 'developer_api1' or 'dev_<hex6>' created or active

`UC_0_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.uri_path) as paths values(Web.http_user_agent) as ua from datamodel=Web where (Web.url="*author=developer_api*" OR Web.url="*author=dev_*" OR Web.url="*user_login=developer_api*" OR Web.url="*user_login=dev_*" OR Web.uri_query="*developer_api1*" OR Web.uri_query="*customer1usx@gmail.com*") by Web.src, Web.dest, Web.user, Web.url | `drop_dm_object_name(Web)` | append [ | tstats `summariesonly` count from datamodel=Change where Change.object_category="user" AND Change.action IN ("created","modified") AND (Change.object="developer_api*" OR Change.object="dev_*") by Change.src, Change.user, Change.object, Change.action | `drop_dm_object_name(Change)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badNames = dynamic([@"^developer_api\d+$", @"^dev_[a-f0-9]{6}$"]);
union
( DeviceLogonEvents
  | where Timestamp > ago(30d)
  | where AccountName matches regex @"(?i)^(developer_api\d+|dev_[a-f0-9]{6})$"
  | project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, ActionType, Source="DeviceLogon" ),
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where AccountName matches regex @"(?i)^(developer_api\d+|dev_[a-f0-9]{6})$"
     or ProcessCommandLine has_any ("developer_api1","customer1usx@gmail.com")
     or ProcessCommandLine matches regex @"(?i)wp\s+user\s+create\s+(developer_api\d+|dev_[a-f0-9]{6})"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source="DeviceProcess" ),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath has "wp-content"
  | where FileName has_any ("developer_api1","customer1usx")
  | project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, Source="DeviceFile" )
| order by Timestamp desc
```

### Backdoor plugin directory 'content-delivery-helper' or 'database-optimizer' under wp-content/plugins

`UC_0_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process_id) as pids from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*wp-content/plugins/content-delivery-helper/*" OR Filesystem.file_path="*wp-content/plugins/database-optimizer/*" OR Filesystem.file_path="*wp-content\\plugins\\content-delivery-helper\\*" OR Filesystem.file_path="*wp-content\\plugins\\database-optimizer\\*") AND Filesystem.action IN ("created","modified","written") by Filesystem.dest, Filesystem.file_path, Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"(?i)[\\/]wp-content[\\/]plugins[\\/](content-delivery-helper|database-optimizer)([\\/]|$)"
   or FileName in~ ("content-delivery-helper.php","database-optimizer.php")
| extend BackdoorVariant = case(
    FolderPath has "content-delivery-helper", "Content Delivery Helper v2.7.1",
    FolderPath has "database-optimizer", "Database Optimizer v2.9.4",
    "unknown")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, FileSize, BackdoorVariant,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### PHP/web-server process spawning shell child from backdoor plugin path (WPM File Manager web shell)

`UC_0_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","httpd","apache2","nginx","w3wp.exe") AND ( Processes.process_name IN ("sh","bash","dash","zsh","ksh","perl","python","python3","cmd.exe","powershell.exe","curl","wget","nc","ncat") OR Processes.process IN ("*content-delivery-helper*","*database-optimizer*","*WPM File Manager*","*wpm_file_manager*") ) by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("php-fpm","php-fpm7.4","php-fpm8.0","php-fpm8.1","php-fpm8.2","httpd","apache2","nginx","w3wp.exe")
| where (FileName in~ ("sh","bash","dash","zsh","ksh","perl","python","python3","cmd.exe","powershell.exe","pwsh.exe","curl","wget","nc","ncat","socat"))
   or InitiatingProcessFolderPath matches regex @"(?i)[\\/]wp-content[\\/]plugins[\\/](content-delivery-helper|database-optimizer)([\\/]|$)"
   or ProcessCommandLine has_any ("content-delivery-helper","database-optimizer","WPM File Manager","wpm_file_manager","wpm-file-manager")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — OptinMonster WordPress plugin hacked in CDN supply-chain attack

`UC_0_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — OptinMonster WordPress plugin hacked in CDN supply-chain attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("min.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("min.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — OptinMonster WordPress plugin hacked in CDN supply-chain attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("min.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("min.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `84.201.6.54`, `tidio.cc`, `a.omappapi.com`, `a.opmnstr.com`, `a.optnmstr.com`, `a.trstplse.com`, `clientcdn.pushengage.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
