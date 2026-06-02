# [HIGH] Laravel-Lang PHP Packages Compromised to Deliver Cross-Platform Credential Stealer

**Source:** The Hacker News
**Published:** 2026-05-23
**Article:** https://thehackernews.com/2026/05/laravel-lang-php-packages-compromised.html

## Threat Profile

Laravel-Lang PHP Packages Compromised to Deliver Cross-Platform Credential Stealer 
 Ravie Lakshmanan  May 23, 2026 Supply Chain Attack / Malware 
Cybersecurity researchers have flagged a fresh software supply chain attack campaign that has targeted multiple PHP packages belonging to Laravel-Lang to deliver a comprehensive credential-stealing framework.
The affected packages include -
laravel-lang/lang
laravel-lang/http-statuses
laravel-lang/attributes
laravel-lang/actions
"The timing and patt…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `flipboxstudio.info`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1059.004** — Unix Shell
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555.005** — Credentials from Password Stores: Password Managers
- **T1041** — Exfiltration Over C2 Channel
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1580** — Cloud Infrastructure Discovery
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PHP/web-server process beaconing to flipboxstudio.info

`UC_138_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic where All_Traffic.dest="flipboxstudio.info" OR All_Traffic.url="*flipboxstudio.info*" by All_Traffic.src host All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | where match(process_name, "(?i)php|php-fpm|httpd|nginx|apache2|w3wp")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "flipboxstudio.info" or RemoteUrl has "flipboxstudio[.]info"
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe","nginx.exe","w3wp.exe","php","php-fpm","httpd","nginx","apache2")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] php-fpm/php-cli spawning cscript.exe with VBS launcher (Laravel-Lang dropper)

`UC_138_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe","nginx.exe","w3wp.exe") Processes.process_name="cscript.exe" Processes.process="*.vbs*" by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe","nginx.exe","w3wp.exe")
| where FileName =~ "cscript.exe"
| where ProcessCommandLine has ".vbs" or ProcessCommandLine has_any (@"\Temp\", @"\AppData\Local\Temp\", "/tmp/")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Mass credential-file fan-out reads from single PHP/www-data process

`UC_138_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Filesystem.file_path) as file_count values(Filesystem.file_path) as files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("php.exe","php-fpm.exe","php-cgi.exe","php","php-fpm","httpd","nginx","apache2","w3wp.exe") (Filesystem.file_path="*.aws/credentials*" OR Filesystem.file_path="*.ssh/id_*" OR Filesystem.file_path="*.kube/config*" OR Filesystem.file_path="*wp-config.php*" OR Filesystem.file_path="*.env*" OR Filesystem.file_path="*.git-credentials*" OR Filesystem.file_path="*.netrc*" OR Filesystem.file_path="*docker-compose.yml*" OR Filesystem.file_path="*Login Data*" OR Filesystem.file_path="*Cookies*") by host Filesystem.process_id Filesystem.process_name _time span=1m | `drop_dm_object_name(Filesystem)` | where file_count >= 5
```

**Defender KQL:**
```kql
let credPaths = dynamic([@"\.aws\credentials", @"\.aws\config", @"\.ssh\id_", @"\.kube\config", @"\.config\gcloud", @"\.git-credentials", @"\.netrc", @"\.gitconfig", "wp-config.php", "docker-compose.yml", ".env", "Login Data", "Cookies", "key3.db", "key4.db", "logins.json", "signons.sqlite", "NordPass", "Bitwarden", "1Password", "LastPass", "KeePass", "electrum", "exodus", "Ledger Live"]);
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated","FileModified","FileRenamed") or ActionType startswith "File"
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe","nginx.exe","w3wp.exe","php","php-fpm","httpd","nginx","apache2")
| where FolderPath has_any (credPaths) or FileName has_any (credPaths)
| summarize FileCount = dcount(strcat(FolderPath, FileName)),
            Files = make_set(strcat(FolderPath, FileName), 30),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
  by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessAccountName
| where FileCount >= 5
| extend SpanSeconds = datetime_diff('second', LastSeen, FirstSeen)
| where SpanSeconds <= 300
| order by LastSeen desc
```

### [LLM] AES-encrypted exfil POST to flipboxstudio.info/exfil

`UC_138_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.bytes_out) as bytes_out values(Web.user_agent) as ua from datamodel=Web where Web.url="*flipboxstudio.info/exfil*" OR (Web.dest="flipboxstudio.info" Web.http_method="POST") by Web.src host Web.http_method Web.url | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "flipboxstudio.info/exfil" or (RemoteUrl has "flipboxstudio.info" and InitiatingProcessFileName in~ ("php.exe","php-fpm.exe","php-cgi.exe","httpd.exe","nginx.exe","w3wp.exe","php","php-fpm","httpd","nginx","apache2"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] PHP/web-server worker querying cloud metadata IMDS endpoints

`UC_138_12` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.url) as urls from datamodel=Network_Traffic where (All_Traffic.dest="169.254.169.254" OR All_Traffic.dest="metadata.google.internal" OR All_Traffic.url="*metadata.google.internal*") All_Traffic.process_name IN ("php.exe","php-fpm.exe","php-cgi.exe","httpd.exe","nginx.exe","apache2","php","php-fpm","w3wp.exe") by host All_Traffic.process_name All_Traffic.user | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where (RemoteIP == "169.254.169.254" or RemoteUrl has "metadata.google.internal" or RemoteUrl has "169.254.169.254")
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe","nginx.exe","w3wp.exe","php","php-fpm","httpd","nginx","apache2")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] helpers.php write under vendor/laravel-lang and composer autoload tampering

`UC_138_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*vendor/laravel-lang/*" Filesystem.file_name="helpers.php") OR (Filesystem.file_path="*vendor/composer/autoload_files.php") OR (Filesystem.file_path="*composer.lock" Filesystem.action IN ("created","modified")) by host Filesystem.process_name Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "vendor" and FolderPath has "laravel-lang" and FileName =~ "helpers.php")
   or (FolderPath has "vendor" and FolderPath has "composer" and FileName =~ "autoload_files.php")
   or (FileName =~ "composer.lock")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `flipboxstudio.info`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
