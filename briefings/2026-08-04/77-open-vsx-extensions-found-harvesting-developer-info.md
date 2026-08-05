# [HIGH] 77 Open VSX extensions found harvesting developer info

**Source:** BleepingComputer
**Published:** 2026-08-04
**Article:** https://www.bleepingcomputer.com/news/security/77-open-vsx-extensions-found-harvesting-developer-info/

## Threat Profile

77 Open VSX extensions found harvesting developer info 
By Lawrence Abrams 
August 4, 2026
02:50 PM
0 
77 extensions on the Open VSX marketplace impersonated legitimate developer tools while transmitting information about the systems and development environments where they were installed.
The so-called "evil twin" campaign was discovered by Manifold Security , which detected the extensions between July 26 and August 1, 2026. Researchers linked all 77 extensions to the same activity through a sha…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `mangorbit.com`
- **Domain (defanged):** `pulse.mangorbit.com`
- **Domain (defanged):** `pulse2.mangorbit.com`
- **Domain (defanged):** `api.mangorbit.com`
- **Domain (defanged):** `cb.mangorbit.com`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1176.002** — Software Extensions: IDE Extensions
- **T1071.004** — Application Layer Protocol: DNS
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Open VSX evil-twin extension exfiltration to mangorbit[.]com C2 infrastructure

`UC_30_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*mangorbit.com*" by DNS.src DNS.dest DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| append [| tstats summariesonly=t allow_old_summaries=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="*mangorbit.com*" by All_Traffic.src All_Traffic.dest All_Traffic.app]
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "mangorbit"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ActionType, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Code editor / node extension-host resolving mangorbit[.]com (evil-twin attribution)

`UC_30_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t allow_old_summaries=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*mangorbit.com*" by DNS.src DNS.query DNS.record_type
| rename DNS.src as src
| join type=inner src [
    | tstats summariesonly=t allow_old_summaries=t values(Processes.process_name) as editor_procs from datamodel=Endpoint.Processes where (Processes.process_name IN ("code.exe","cursor.exe","windsurf.exe","vscodium.exe","node.exe")) by Processes.dest
    | rename Processes.dest as src ]
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| table firstTime lastTime src editor_procs DNS.query DNS.record_type count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "mangorbit"
| where InitiatingProcessFileName in~ ("code.exe","cursor.exe","windsurf.exe","vscodium.exe","node.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
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

### Article-specific behavioural hunt — 77 Open VSX extensions found harvesting developer info

`UC_30_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 77 Open VSX extensions found harvesting developer info ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("extension.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("extension.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 77 Open VSX extensions found harvesting developer info
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("extension.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("extension.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `mangorbit.com`, `pulse.mangorbit.com`, `pulse2.mangorbit.com`, `api.mangorbit.com`, `cb.mangorbit.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
