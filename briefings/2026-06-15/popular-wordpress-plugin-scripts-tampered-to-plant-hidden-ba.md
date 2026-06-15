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
- **T1567** — Exfiltration Over Web Service
- **T1583.001** — Acquire Infrastructure: Domains
- **T1505.003** — Server Software Component: Web Shell
- **T1505** — Server Software Component
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1041** — Exfiltration Over C2 Channel
- **T1567.002** — Exfiltration to Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Egress to Awesome Motive backdoor C2 (tidio.cc / 84.201.6.54)

`UC_2_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as http_method values(Web.user_agent) as user_agent from datamodel=Web.Web where (Web.dest="84.201.6.54" OR Web.url="*tidio.cc*" OR Web.dest="tidio.cc") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="84.201.6.54" OR All_Traffic.dest_host="tidio.cc" OR All_Traffic.dest_host="*.tidio.cc") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host | `drop_dm_object_name(All_Traffic)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_ips = dynamic(["84.201.6.54"]);
let bad_domains = dynamic(["tidio.cc",".tidio.cc"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (bad_ips)
   or RemoteUrl has_any (bad_domains)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp asc
```

### Rogue WordPress backdoor plugin folder created (content-delivery-helper / database-optimizer)

`UC_2_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*/wp-content/plugins/content-delivery-helper/*" OR Filesystem.file_path="*/wp-content/plugins/database-optimizer/*") by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has_any ("/wp-content/plugins/content-delivery-helper",
                            "/wp-content/plugins/database-optimizer",
                            @"\wp-content\plugins\content-delivery-helper",
                            @"\wp-content\plugins\database-optimizer")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp asc
```

### Web access to backdoor /cdn-cgi/ paths on tidio.cc lookalike domain

`UC_2_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as http_method values(Web.user_agent) as user_agent values(Web.bytes_out) as bytes_out from datamodel=Web.Web where (Web.url="*tidio.cc/cdn-cgi/*" OR (Web.dest="tidio.cc" AND Web.url="*/cdn-cgi/*") OR Web.dest="84.201.6.54") by Web.src Web.dest Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | where http_method="POST" OR bytes_out>500
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where (RemoteUrl has "tidio.cc" and RemoteUrl has "/cdn-cgi/")
     or (RemoteIP == "84.201.6.54")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
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

`UC_2_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
