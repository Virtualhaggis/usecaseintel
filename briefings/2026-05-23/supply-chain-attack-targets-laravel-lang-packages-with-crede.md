# [HIGH] Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer

**Source:** Aikido
**Published:** 2026-05-23
**Article:** https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer

## Threat Profile

Blog Vulnerabilities & Threats Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer Written by Ilyas Makari Published on: May 23, 2026 On May 22, 2026, we detected an active supply chain attack against Laravel-Lang. We filed a report with the maintainers immediately. The attacker published malicious version tags across three widely used repositories, injecting credential-stealing code that loads automa…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `flipboxstudio.info`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1132.001** — Data Encoding: Standard Encoding
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1140** — Deobfuscate/Decode Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] C2 egress to flipboxstudio.info from Laravel-Lang composer dropper

`UC_3_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as queries values(DNS.answer) as answers from datamodel=Network_Resolution where DNS.query="flipboxstudio.info" OR DNS.query="*.flipboxstudio.info" by DNS.src host
| `drop_dm_object_name(DNS)`
| appendpipe [
    | tstats summariesonly=true count from datamodel=Web where Web.url="*flipboxstudio.info*" OR Web.url="*flipboxstudio.info/payload*" OR Web.url="*flipboxstudio.info/exfil*" by Web.src Web.dest Web.url Web.http_user_agent
    | `drop_dm_object_name(Web)`
  ]
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let C2Host = "flipboxstudio.info";
union isfuzzy=true
(
  DeviceNetworkEvents
  | where Timestamp > ago(LookbackDays)
  | where RemoteUrl has C2Host or RemoteUrl has "flipboxstudio.info/payload" or RemoteUrl has "flipboxstudio.info/exfil"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            RemoteUrl, RemoteIP, RemotePort, ActionType
),
(
  DeviceEvents
  | where Timestamp > ago(LookbackDays)
  | where ActionType == "DnsQueryResponse" or ActionType == "InboundConnectionAccepted"
  | where AdditionalFields has C2Host
  | project Timestamp, DeviceName, AccountName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            RemoteIP, AdditionalFields, ActionType
)
| order by Timestamp desc
```

### [LLM] cscript.exe launching .vbs from .laravel_locale temp directory

`UC_3_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where Processes.process_name="cscript.exe" AND (Processes.process="*\\.laravel_locale\\*.vbs*" OR Processes.process="*/.laravel_locale/*.vbs*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName =~ "cscript.exe" or FileName =~ "wscript.exe"
| where ProcessCommandLine has @".laravel_locale"
   and ProcessCommandLine matches regex @"(?i)\.laravel_locale[\\/][0-9a-f]{8}\.vbs"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFileName,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Composer install of malicious helpers.php in laravel-lang vendor package

`UC_3_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*vendor/laravel-lang/lang/src/helpers.php" OR Filesystem.file_path="*vendor/laravel-lang/attributes/src/helpers.php" OR Filesystem.file_path="*vendor/laravel-lang/http-statuses/src/helpers.php" OR Filesystem.file_path="*vendor\\laravel-lang\\lang\\src\\helpers.php" OR Filesystem.file_path="*vendor\\laravel-lang\\attributes\\src\\helpers.php" OR Filesystem.file_path="*vendor\\laravel-lang\\http-statuses\\src\\helpers.php") by Filesystem.dest Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName =~ "helpers.php"
| where FolderPath matches regex @"(?i)[\\\\/]vendor[\\\\/]laravel-lang[\\\\/](lang|attributes|http-statuses)[\\\\/]src[\\\\/]?$"
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### [LLM] Stealer or VBS launcher dropped into .laravel_locale temp directory

`UC_3_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.laravel_locale\\*" OR Filesystem.file_path="*/.laravel_locale/*") by Filesystem.dest Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| where match(file_name, "(?i)^[0-9a-f]{12}\.php$") OR match(file_name, "(?i)^[0-9a-f]{8}\.vbs$") OR match(file_name, "(?i)^[0-9a-f]{32}$")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has @".laravel_locale" or FolderPath has @"/.laravel_locale/" or FolderPath has @"\\.laravel_locale\\"
| where (FileName matches regex @"(?i)^[0-9a-f]{12}\.php$")
     or (FileName matches regex @"(?i)^[0-9a-f]{8}\.vbs$")
     or (FileName matches regex @"(?i)^[0-9a-f]{32}$")
| project Timestamp, DeviceName, FolderPath, FileName, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
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

### Article-specific behavioural hunt — Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer

`UC_3_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("settings.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/kubernetes/admin.conf*" OR Filesystem.file_name IN ("settings.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Supply Chain Attack Targets Laravel-Lang Packages with Credential Stealer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("settings.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/kubernetes/admin.conf") or FileName in~ ("settings.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `flipboxstudio.info`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
