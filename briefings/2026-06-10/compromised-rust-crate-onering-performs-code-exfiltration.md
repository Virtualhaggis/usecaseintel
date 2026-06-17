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
- **T1567.002** — Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1005** — Data from Local System
- **T1083** — File and Directory Discovery
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1554** — Compromise Host Software Binary
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound traffic to onering crate's Sentry-disguised exfil endpoint

`UC_121_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.user_agent) as ua values(Web.dest_ip) as dest from datamodel=Web.Web where (Web.url="*o4511539639222272.ingest.de.sentry.io*" OR Web.url="*4511539669368912/envelope*" OR Web.dest="o4511539639222272.ingest.de.sentry.io") by Web.src host Web.user | `drop_dm_object_name("Web")` | append [ | tstats summariesonly=true count from datamodel=Network_Resolution where DNS.query="o4511539639222272.ingest.de.sentry.io" OR DNS.query="*o4511539639222272*" by DNS.src host DNS.query | `drop_dm_object_name("DNS")`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SentryHost = "o4511539639222272.ingest.de.sentry.io";
let SentryPath = "4511539669368912/envelope";
union isfuzzy=true
(
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has SentryHost or RemoteUrl has SentryPath
    | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, Source = "DeviceNetworkEvents"
),
(
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where AdditionalFields has SentryHost or RemoteUrl has SentryHost
    | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort = int(null), Source = "DnsQueryResponse"
)
| order by Timestamp desc
```

### Cargo/rustc build script spawning curl POST to Sentry envelope endpoint

`UC_121_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe","Invoke-WebRequest")) (Processes.parent_process_name IN ("cargo.exe","cargo","rustc.exe","rustc") OR Processes.parent_process_name="build-script-build*" OR Processes.parent_process="*build-script-build*") (Processes.process="*sentry.io*" OR Processes.process="*envelope*" OR Processes.process="*x-sentry-envelope*" OR Processes.process="*8197ee42c4f59c83f4cc6d48f5bae821*") by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name("Processes")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe"))
| where (InitiatingProcessFileName in~ ("cargo.exe","cargo","rustc.exe","rustc")
         or InitiatingProcessFileName startswith "build-script-build"
         or InitiatingProcessParentFileName in~ ("cargo.exe","cargo","rustc.exe","rustc")
         or InitiatingProcessParentFileName startswith "build-script-build")
| where ProcessCommandLine has_any ("sentry.io","envelope","x-sentry-envelope","8197ee42c4f59c83f4cc6d48f5bae821","o4511539639222272","4511539669368912")
| project Timestamp, DeviceName, AccountName, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Cargo build script invoking git diff HEAD^ HEAD on consuming repository

`UC_121_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="git") (Processes.process="*diff HEAD^ HEAD*" OR Processes.process="*log -n 1 --pretty=format*" OR Processes.process="*--pretty=format:{\"commit\"*") (Processes.parent_process_name IN ("cargo.exe","cargo","rustc.exe","rustc") OR Processes.parent_process_name="build-script-build*" OR Processes.parent_process="*build-script-build*" OR Processes.parent_process="*\\target\\debug\\build\\*" OR Processes.parent_process="*/target/debug/build/*" OR Processes.parent_process="*/target/release/build/*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name("Processes")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","git")
| where ProcessCommandLine has_any ("diff HEAD^ HEAD", "log -n 1 --pretty=format", "--pretty=format:{\"commit\"")
| where InitiatingProcessFileName in~ ("cargo.exe","cargo","rustc.exe","rustc")
      or InitiatingProcessFileName startswith "build-script-build"
      or InitiatingProcessParentFileName in~ ("cargo.exe","cargo","rustc.exe","rustc")
      or InitiatingProcessParentFileName startswith "build-script-build"
      or InitiatingProcessFolderPath has @"\target\debug\build\"
      or InitiatingProcessFolderPath has @"\target\release\build\"
      or InitiatingProcessFolderPath has "/target/debug/build/"
      or InitiatingProcessFolderPath has "/target/release/build/"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp desc
```

### Malicious onering crate v1.4.1 unpacked into Cargo registry source cache

`UC_121_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.cargo\\registry\\src\\*onering-1.4.1*" OR Filesystem.file_path="*/.cargo/registry/src/*onering-1.4.1*" OR Filesystem.file_path="*\\onering-1.4.1\\build.rs" OR Filesystem.file_path="*/onering-1.4.1/build.rs") by host Filesystem.user Filesystem.file_name | `drop_dm_object_name("Filesystem")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where (FolderPath has @"\.cargo\registry\src\" and FolderPath has "onering-1.4.1")
      or (FolderPath has "/.cargo/registry/src/" and FolderPath has "onering-1.4.1")
      or (FolderPath has "onering-1.4.1" and FileName == "build.rs")
      or (FolderPath has "onering-1.4.1" and FileName == "Cargo.toml")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Rust build-script-build binary opening outbound public network connections

`UC_121_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as proc from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="*build-script-build*" OR All_Traffic.process_name="build-script-build*" OR All_Traffic.process="*build-script-build*") NOT (All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip=172.16.0.0/12 OR All_Traffic.dest_ip=127.0.0.0/8 OR All_Traffic.dest_ip=169.254.0.0/16) by host All_Traffic.user All_Traffic.app | `drop_dm_object_name("All_Traffic")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName startswith "build-script-build"
      or InitiatingProcessFolderPath has @"\target\debug\build\"
      or InitiatingProcessFolderPath has @"\target\release\build\"
      or InitiatingProcessFolderPath has "/target/debug/build/"
      or InitiatingProcessFolderPath has "/target/release/build/"
| where RemoteIPType == "Public"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","ConnectionRequest")
| extend CrateName = extract(@"build[\\/]([^\\/]+)-[0-9a-f]+[\\/]build-script", 1, InitiatingProcessFolderPath)
| project Timestamp, DeviceName, InitiatingProcessFolderPath, InitiatingProcessFileName, CrateName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
