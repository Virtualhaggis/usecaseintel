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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1005** — Data from Local System
- **T1041** — Exfiltration Over C2 Channel
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Network callback to onering supply-chain Sentry ingest endpoint

`UC_121_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as process from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="o4511539639222272.ingest.de.sentry.io" OR All_Traffic.url="*o4511539639222272.ingest.de.sentry.io*" OR All_Traffic.url="*api/4511539669368912/envelope*") by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "o4511539639222272.ingest.de.sentry.io"
    or RemoteUrl has "4511539669368912/envelope"
| project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Cargo build-script-build process for compromised onering crate

`UC_121_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_path="*\\target\\debug\\build\\onering-*\\build-script-build*" OR Processes.process_path="*\\target\\release\\build\\onering-*\\build-script-build*" OR Processes.process_path="*/target/debug/build/onering-*/build-script-build*" OR Processes.process_path="*/target/release/build/onering-*/build-script-build*") by Processes.dest Processes.user Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath has @"\target\debug\build\onering-" or FolderPath has @"\target\release\build\onering-"
      or FolderPath has "/target/debug/build/onering-" or FolderPath has "/target/release/build/onering-")
| where FileName has "build-script-build" or FileName has "build_script_build"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Build-time git log/diff invocation matching onering exfiltration pattern

`UC_121_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="git") (Processes.process="*--pretty=format:{\"commit\":\"%H\"*" OR Processes.process="*diff HEAD^ HEAD*") (Processes.parent_process_name="build-script-build*" OR Processes.parent_process_name="build_script_build*" OR Processes.parent_process_name="cargo.exe" OR Processes.parent_process_name="cargo" OR Processes.parent_process_name="rustc.exe" OR Processes.parent_process_name="rustc") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe", "git")
| where ProcessCommandLine has @"--pretty=format:{""commit"":""%H"""
    or ProcessCommandLine has "diff HEAD^ HEAD"
    or ProcessCommandLine matches regex @"(?i)diff\s+HEAD\^\s+HEAD\b"
| where InitiatingProcessFileName has_any ("build-script-build", "build_script_build", "cargo.exe", "cargo", "rustc.exe", "rustc")
    or InitiatingProcessParentFileName has_any ("build-script-build", "build_script_build", "cargo.exe", "cargo")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### curl POST to Sentry envelope endpoint from Cargo build context

`UC_121_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="curl.exe" OR Processes.process_name="curl") (Processes.process="*o4511539639222272.ingest.de.sentry.io*" OR Processes.process="*application/x-sentry-envelope*" OR Processes.process="*api/4511539669368912/envelope*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe", "curl")
| where ProcessCommandLine has_any (
        "o4511539639222272.ingest.de.sentry.io",
        "application/x-sentry-envelope",
        "/api/4511539669368912/envelope"
      )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          SHA256
| order by Timestamp desc
```

### Cargo build script spawning network or shell utilities

`UC_121_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.parent_process_path) as parent_path from datamodel=Endpoint.Processes where (Processes.parent_process_name="build-script-build*" OR Processes.parent_process_name="build_script_build*" OR Processes.parent_process_path="*\\target\\*\\build\\*\\build-script-build*" OR Processes.parent_process_path="*/target/*/build/*/build-script-build*") (Processes.process_name IN ("curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe","bitsadmin.exe","certutil.exe","git.exe","git","tar.exe","tar","zip","7z.exe","sh","bash","cmd.exe")) by Processes.dest Processes.user Processes.parent_process_path Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("build-script-build", "build_script_build")
   or InitiatingProcessFolderPath matches regex @"(?i)[\\/]target[\\/](debug|release)[\\/]build[\\/][^\\/]+[\\/]"
| where FileName in~ (
        "curl.exe","curl","wget.exe","wget",
        "powershell.exe","pwsh.exe","bitsadmin.exe","certutil.exe",
        "git.exe","git","tar.exe","tar","zip.exe","zip","7z.exe",
        "sh","bash","cmd.exe","nc.exe","nc","ncat.exe","ncat"
      )
| where AccountName !endswith "$"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Hits = count(), SampleCmd = any(ProcessCommandLine)
            by DeviceName, AccountName, FileName,
               CrateBuildScript = tostring(extract(@"(?i)[\\/]target[\\/](?:debug|release)[\\/]build[\\/]([^\\/]+)[\\/]", 1, InitiatingProcessFolderPath))
| order by LastSeen desc
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
