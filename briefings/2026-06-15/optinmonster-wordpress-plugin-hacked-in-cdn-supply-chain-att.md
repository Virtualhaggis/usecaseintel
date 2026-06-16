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
E-commerce security firm Sansec discovered the attack over the we…

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
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1189** — Drive-by Compromise
- **T1539** — Steal Web Session Cookie
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1041** — Exfiltration Over C2 Channel
- **T1505.003** — Server Software Component: Web Shell
- **T1543** — Create or Modify System Process
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1136.001** — Create Account: Local Account
- **T1078.001** — Valid Accounts: Default Accounts
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### WP admin browser loads poisoned Awesome Motive CDN api.min.js (OptinMonster/TrustPulse/PushEngage)

`UC_19_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents from datamodel=Web where (Web.url="*a.omappapi.com/app/js/api.min.js*" OR Web.url="*a.opmnstr.com/app/js/api.min.js*" OR Web.url="*a.optnmstr.com/app/js/api.min.js*" OR Web.url="*a.trstplse.com/app/js/api.min.js*" OR Web.url="*clientcdn.pushengage.com*") by Web.src Web.user Web.dest
| `drop_dm_object_name(Web)`
| eval window_start=strptime("2026-06-12 22:17:00","%Y-%m-%d %H:%M:%S"), window_end=strptime("2026-06-13 19:02:00","%Y-%m-%d %H:%M:%S")
| where firstTime>=window_start AND firstTime<=window_end
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MaliciousPaths = dynamic([
  "a.omappapi.com/app/js/api.min.js",
  "a.opmnstr.com/app/js/api.min.js",
  "a.optnmstr.com/app/js/api.min.js",
  "a.trstplse.com/app/js/api.min.js",
  "clientcdn.pushengage.com"
]);
let WindowStart = datetime(2026-06-12T22:17:00Z);
let WindowEnd = datetime(2026-06-13T19:02:00Z);
DeviceNetworkEvents
| where Timestamp between (WindowStart .. WindowEnd)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")
| where RemoteUrl has_any (MaliciousPaths)
| project Timestamp, DeviceName, InitiatingProcessAccountName, AccountUpn=InitiatingProcessAccountUpn, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### Outbound C2 to Tidio-impersonating exfil host (tidio.cc / 84.201.6.54)

`UC_19_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as queries values(DNS.answer) as answers from datamodel=Network_Resolution where (DNS.query="tidio.cc" OR DNS.query="*.tidio.cc") by DNS.src DNS.dest
| `drop_dm_object_name(DNS)`
| append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports from datamodel=Network_Traffic where All_Traffic.dest="84.201.6.54" by All_Traffic.src All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`]
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "tidio.cc" or RemoteIP == "84.201.6.54"
| where not(RemoteUrl has "tidio.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Backdoor WordPress plugin folder created (Content Delivery Helper / Database Optimizer)

`UC_19_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process_name) as creators from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_path="*wp-content/plugins/*" AND (Filesystem.file_path="*content-delivery-helper*" OR Filesystem.file_path="*database-optimizer*") by Filesystem.dest Filesystem.file_path Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FolderPath has "wp-content/plugins/"
| where FolderPath has_any ("content-delivery-helper","database-optimizer")
   or FileName has_any ("content-delivery-helper","database-optimizer")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RequestAccountName
| order by Timestamp desc
```

### Rogue WordPress administrator account created (developer_api1 / dev_xxxxxx pattern)

`UC_19_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.process="*wp user create developer_api1*" OR Processes.process="*wp user create dev_*" OR Processes.process="*--role=administrator*developer_api1*" OR Processes.process="*--role=administrator*dev_*") by Processes.dest Processes.user Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append [| tstats summariesonly=true count from datamodel=Web where Web.uri_path="*wp-admin/user-new.php*" by Web.src Web.dest Web.user Web.url
| `drop_dm_object_name(Web)`]
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has "wp" and ProcessCommandLine has "user" and ProcessCommandLine has "create"
    | where ProcessCommandLine has "developer_api1" or ProcessCommandLine matches regex @"\bdev_[A-Za-z0-9]{4,}\b"
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, Signal="WP-CLI create"),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("php","php-fpm","php-cgi","php8.2","php8.1","www-data","apache2","nginx")
    | where ProcessCommandLine has_any ("developer_api1","dev_api","INSERT INTO wp_users")
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, Signal="Webserver-spawned")
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

`UC_19_2` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
