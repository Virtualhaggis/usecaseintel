# [CRIT] Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install

**Source:** The Hacker News
**Published:** 2026-07-11
**Article:** https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html

## Threat Profile

Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install 
 Swati Khandelwal  Jul 11, 2026 Software Supply Chain / Malware 
The jscrambler npm package was compromised, and simply installing its 8.14.0 release runs an infostealer on your machine. Published on July 11, 2026, the malicious version carries a preinstall hook that drops and executes a native binary, one build each for Windows, macOS, and Linux.
Socket flagged the release  six minutes after it was published . If…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `37.27.122.124`
- **IPv4 (defanged):** `57.128.246.79`
- **SHA256:** `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`
- **SHA256:** `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`
- **SHA256:** `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`
- **SHA256:** `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`
- **SHA256:** `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1053.005** — Scheduled Task
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1543.001** — Persistence (article-specific)
- **T1204.003** — Malicious Package
- **T1059.007** — JavaScript
- **T1564.001** — Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web
- **T1573.002** — Asymmetric Cryptography
- **T1090.003** — Multi-hop Proxy
- **T1552.001** — Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Tampered jscrambler@8.14.0 package files (dist/setup.js, dist/intro.js) written to node_modules

`UC_0_8` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60","a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86") OR (Filesystem.file_name IN ("setup.js","intro.js") AND Filesystem.file_path="*node_modules*jscrambler*dist*")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where SHA256 in ("a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60","a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86")
   or (FileName in~ ("setup.js","intro.js") and FolderPath has @"\node_modules\jscrambler\dist\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### npm preinstall hook (node.exe) launches detached hidden binary from temp directory

`UC_0_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.exe","node") AND (Processes.process_hash IN ("fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd","b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903","c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd") OR (Processes.process_path IN ("*\\AppData\\Local\\Temp\\*","*\\Windows\\Temp\\*","/tmp/*","/var/folders/*") AND Processes.process_name IN (".*"))) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where match(process_name,"^\.") OR isnotnull(process_hash) | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","node")
| where SHA256 in ("fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd","b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903","c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd")
   or (FolderPath has_any (@"\AppData\Local\Temp\", @"\Windows\Temp\", "/tmp/", "/var/folders/") and FileName matches regex @"^\.[A-Za-z0-9._-]+(\.exe)?$")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### jscrambler stealer C2 beacon to 37.27.122.124 / 57.128.246.79 and Tor bootstrap

`UC_0_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("37.27.122.124","57.128.246.79") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("37.27.122.124","57.128.246.79")
   or RemoteUrl in~ ("check.torproject.org","archive.torproject.org")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Every-minute relaunch of hidden temp binary via Task Scheduler (jscrambler stealer persistence)

`UC_0_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime dc(_time) as runbuckets from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("svchost.exe","taskeng.exe") AND Processes.process_path IN ("*\\AppData\\Local\\Temp\\*","*\\Windows\\Temp\\*") by Processes.dest Processes.process_name Processes.process_path Processes.process_hash span=1h | `drop_dm_object_name(Processes)` | where match(process_name,"^\.") AND count >= 10 | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("svchost.exe","taskeng.exe")
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\Windows\Temp\")
| where FileName matches regex @"^\.[A-Za-z0-9._-]+(\.exe)?$"
| summarize Runs=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SampleCmd=any(ProcessCommandLine) by DeviceName, FileName, FolderPath, SHA256, bin(Timestamp, 1h)
| where Runs >= 10   // minute-interval task => ~60 launches/hr; 10 well above benign scheduled jobs
| order by Runs desc
```

### Temp-dir binary harvesting cloud/browser/AI-tool secrets after jscrambler install

`UC_0_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.process_path IN ("*\\AppData\\Local\\Temp\\*","*\\Windows\\Temp\\*","/tmp/*","/var/folders/*")) AND (Filesystem.file_path IN ("*\\.aws\\credentials","*\\.config\\gcloud\\*","*\\.azure\\*","*\\Google\\Chrome\\*\\Login Data","*\\Microsoft\\Edge\\*\\Login Data","*\\Bitwarden*","*\\Claude\\*","*\\Cursor\\*","*\\Windsurf\\*","*\\.codeium\\*","*\\Zed\\*","*\\Code\\User\\*")) by Filesystem.dest Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | eval secret_classes=mvcount(mvdedup(mvmap(paths, case(match(paths,"(?i)\.aws|gcloud|\.azure"),"cloud", match(paths,"(?i)Login Data|Bitwarden"),"vault", match(paths,"(?i)Claude|Cursor|Windsurf|codeium|Zed|Code\\User"),"aitool", true(),"other")))) | where secret_classes >= 2 | sort - count
```

**Defender KQL:**
```kql
let SecretPaths = dynamic([@"\.aws\credentials", @"\.config\gcloud\", @"\.azure\", @"\Login Data", @"Bitwarden", @"\Claude\", @"\Cursor\", @"\Windsurf\", @"\.codeium\", @"\Zed\", @"\Code\User\"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFolderPath has_any (@"\AppData\Local\Temp\", @"\Windows\Temp\", "/tmp/", "/var/folders/")
| where FolderPath has_any (SecretPaths)
| extend Class = case(
    FolderPath has_any (@"\.aws", "gcloud", @"\.azure"), "cloud",
    FolderPath has_any (@"Login Data", "Bitwarden"), "vault",
    FolderPath has_any (@"\Claude", @"\Cursor", @"\Windsurf", @"\.codeium", @"\Zed", @"\Code\User"), "aitool",
    "other")
| summarize DistinctClasses=dcount(Class), Classes=make_set(Class), Files=make_set(FolderPath), Reads=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| where DistinctClasses >= 2   // one temp process touching 2+ secret categories = stealer fan-out
| order by Reads desc
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

### Article-specific behavioural hunt — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install

`UC_0_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.js","intro.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/LaunchAgents*" OR Filesystem.file_name IN ("setup.js","intro.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.js", "intro.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/LaunchAgents") or FileName in~ ("setup.js", "intro.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `37.27.122.124`, `57.128.246.79`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`, `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`, `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`, `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`, `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
