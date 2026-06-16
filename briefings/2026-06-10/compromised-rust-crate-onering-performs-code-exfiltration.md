# [CRIT] Compromised Rust crate onering performs code exfiltration

**Source:** Aikido
**Published:** 2026-06-10
**Article:** https://www.aikido.dev/blog/compromised-rust-crate-onering-performs-code-exfiltration

## Threat Profile

Blog Vulnerabilities & Threats Compromised Rust crate onering performs code exfiltration Compromised Rust crate onering performs code exfiltration Written by Ilyas Makari Published on: Jun 10, 2026 On June 10th 2026, we detected malicious behavior in the latest version, 1.4.1, of the Rust crate "onering". Onering is a high-throughput synchronous queue and channels library for Rust, with over 18,000 downloads on crates.io. In the last few weeks npm, PyPI, and GitHub got most of the attention with…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `o4511539639222272.ingest.de.sentry.io`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059** — Command and Scripting Interpreter
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Cargo build script spawning git with onering's exfil --pretty=format JSON

`UC_103_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("git.exe","git") Processes.process="*log*" Processes.process="*--pretty=format*" Processes.process="*commit*" Processes.process="*%H*" Processes.process="*author*" Processes.process="*%an*" Processes.parent_process_name IN ("build-script-build.exe","build_script_build.exe","build-script-build","cargo.exe","rustc.exe") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("git.exe", "git")
| where ProcessCommandLine has "log"
| where ProcessCommandLine has "--pretty=format"
| where ProcessCommandLine has_all ("commit", "%H", "author", "%an", "email", "%ae")
| where InitiatingProcessFileName has_any ("build-script-build.exe", "build_script_build.exe", "build-script-build", "cargo.exe", "rustc.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### build.rs invoking curl POST to Sentry envelope endpoint with code diff payload

`UC_103_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("curl.exe","curl") (Processes.process="*o4511539639222272.ingest.de.sentry.io*" OR Processes.process="*4511539669368912/envelope*" OR Processes.process="*application/x-sentry-envelope*") Processes.parent_process_name IN ("build-script-build.exe","build_script_build.exe","build-script-build","cargo.exe","rustc.exe") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("curl.exe", "curl")
| where ProcessCommandLine has_any ("o4511539639222272.ingest.de.sentry.io", "4511539669368912/envelope", "application/x-sentry-envelope", "8197ee42c4f59c83f4cc6d48f5bae821")
| where InitiatingProcessFileName has_any ("build-script-build.exe", "build_script_build.exe", "build-script-build", "cargo.exe", "rustc.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Network egress to onering Sentry exfil ingest domain or project envelope path

`UC_103_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*o4511539639222272.ingest.de.sentry.io*" OR Web.url="*/api/4511539669368912/envelope*") by Web.src Web.user Web.url Web.http_method Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "o4511539639222272.ingest.de.sentry.io" or RemoteUrl has "4511539669368912/envelope"
 | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "DnsQueryResponse"
 | where AdditionalFields has "o4511539639222272.ingest.de.sentry.io"
 | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields)
| order by Timestamp desc
```

### Cargo dependency manifest or download pinned to compromised onering 1.4.1

`UC_103_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*crates.io*" OR Web.url="*static.crates.io*") (Web.url="*onering/1.4.1*" OR Web.url="*onering-1.4.1.crate*") by Web.src Web.user Web.url Web.http_method | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "crates.io" and (RemoteUrl has "onering/1.4.1" or RemoteUrl has "onering-1.4.1.crate")
 | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FileName in~ ("Cargo.lock", "Cargo.toml")
 | where InitiatingProcessFileName in~ ("cargo.exe", "cargo")
 | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where FolderPath has ".cargo\\registry\\cache" or FolderPath has ".cargo/registry/cache"
 | where FileName has "onering-1.4.1"
 | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256)
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
  - IP / domain IOC(s): `o4511539639222272.ingest.de.sentry.io`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
