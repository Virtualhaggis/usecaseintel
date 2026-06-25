# [HIGH] Why developer machines are now the number one target for supply chain attacks

**Source:** Aikido
**Published:** 2026-05-26
**Article:** https://www.aikido.dev/blog/developer-machines-supply-chain-attacks

## Threat Profile

Blog News Why developer machines are now the number one target for supply chain attacks Why developer machines are now the number one target for supply chain attacks Written by Sooraj Shah Published on: May 26, 2026 Developer workstations have become the highest-ROI target in software supply chain attacks, and the problem is accelerating. 
“There’s one key metric that concerns me: over the past three months we had seven times more vulnerabilities in our supply chain versus the prior three months…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `api.masscan.cloud`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `filev2.getsession.org`
- **Domain (defanged):** `seed1.getsession.org`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1528** — Steal Application Access Token
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mini Shai-Hulud npm worm C2/exfil egress (masscan.cloud, git-tanstack.com, getsession.org)

`UC_289_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*masscan.cloud" OR DNS.query="*git-tanstack.com" OR DNS.query="*getsession.org") by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("api.masscan.cloud","zero.masscan.cloud","masscan.cloud","git-tanstack.com","filev2.getsession.org","seed1.getsession.org","getsession.org")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Package-manager process harvesting cloud metadata / Vault (IMDS 169.254.169.254, ECS 169.254.170.2, Vault :8200)

`UC_289_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("169.254.169.254","169.254.170.2") OR (All_Traffic.dest="127.0.0.1" AND All_Traffic.dest_port=8200)) AND All_Traffic.app IN ("node","node.exe","npm","npx","bun","bun.exe","yarn","pnpm","python","python3") by All_Traffic.src All_Traffic.app All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where (RemoteIP in ("169.254.169.254","169.254.170.2")) or (RemoteIP == "127.0.0.1" and RemotePort == 8200)
| where InitiatingProcessFileName has_any ("node.exe","node","npm","npm-cli.js","npx","bun.exe","bun","yarn","pnpm","python.exe","python","python3")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by Timestamp desc
```

### Mini Shai-Hulud 'gh-token-monitor' persistence daemon (LaunchAgent / systemd)

`UC_289_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*gh-token-monitor*" OR (Filesystem.file_path IN ("*LaunchAgents*","*LaunchDaemons*","*/etc/systemd/system/*","*.config/systemd/user/*") AND Filesystem.file_name="*token*")) by Filesystem.dest Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName has "gh-token-monitor"
   or (FolderPath has_any ("LaunchAgents","LaunchDaemons","/etc/systemd/system",".config/systemd") and FileName has "token")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### npm/bun process writing GitHub Actions workflow files (worm secret-exfil injection)

`UC_289_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.github\\workflows\\*" OR Filesystem.file_path="*/.github/workflows/*") AND (Filesystem.file_name="*.yml" OR Filesystem.file_name="*.yaml") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\.github\workflows" or FolderPath has "/.github/workflows")
| where FileName endswith ".yml" or FileName endswith ".yaml"
| where InitiatingProcessFileName has_any ("node.exe","node","npm","npm-cli.js","npx","bun.exe","bun","yarn","pnpm")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath
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
  - IP / domain IOC(s): `api.masscan.cloud`, `git-tanstack.com`, `filev2.getsession.org`, `seed1.getsession.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
