# [CRIT] Compromised @injectivelabs/sdk-ts exfiltrates wallet keys through fake telemetry

**Source:** Aikido
**Published:** 2026-07-09
**Article:** https://www.aikido.dev/blog/compromised-injectivelabs-exfiltrates-keys

## Threat Profile

Blog Vulnerabilities & Threats Compromised @injectivelabs/sdk-ts exfiltrates wallet keys through fake telemetry Compromised @injectivelabs/sdk-ts exfiltrates wallet keys through fake telemetry Written by Hunter Schwartz Published on: Jul 9, 2026 A malicious release of @injectivelabs/sdk-ts , an npm package that pulls around 50,000 weekly downloads, shipped code that records wallet mnemonics and private keys as they are derived and ships them to an attacker-controlled endpoint. The bad version, 1…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `testnet.archival.chain.grpc-web.injective.network`
- **SHA256:** `103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0`
- **SHA256:** `9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1132.001** — Data Encoding: Standard Encoding
- **T1041** — Exfiltration Over C2 Channel
- **T1001.003** — Data Obfuscation: Protocol or Service Impersonation
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exfil to lookalike Injective gRPC-web subdomain (@injectivelabs stealer C2)

`UC_134_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="testnet.archival.chain.grpc-web.injective.network" by DNS.src DNS.dest DNS.query
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "testnet.archival.chain.grpc-web.injective.network"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Malicious @injectivelabs SDK build artifact by SHA-256 on disk

`UC_134_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0" OR Filesystem.file_hash="9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in ("103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0", "9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Transitive install of poisoned @injectivelabs 1.20.21 build under node_modules

`UC_134_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="accounts-Cy0p4lLW.cjs" OR Filesystem.file_name="accounts-jQ1GSgaW.js") (Filesystem.file_path="*node_modules*injectivelabs*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("accounts-Cy0p4lLW.cjs", "accounts-jQ1GSgaW.js")
| where FolderPath contains "node_modules" and FolderPath contains "injectivelabs"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — Compromised @injectivelabs/sdk-ts exfiltrates wallet keys through fake telemetry

`UC_134_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Compromised @injectivelabs/sdk-ts exfiltrates wallet keys through fake telemetry ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("jq1gsgaw.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("jq1gsgaw.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Compromised @injectivelabs/sdk-ts exfiltrates wallet keys through fake telemetry
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("jq1gsgaw.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("jq1gsgaw.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `testnet.archival.chain.grpc-web.injective.network`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0`, `9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
