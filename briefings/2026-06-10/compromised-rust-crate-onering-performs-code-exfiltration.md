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
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1059** — Command and Scripting Interpreter
- **T1199** — Trusted Relationship
- **T1213.003** — Data from Information Repositories: Code Repositories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound to onering crate C2 Sentry ingest endpoint (o4511539639222272)

`UC_120_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="o4511539639222272.ingest.de.sentry.io" OR All_Traffic.dest="*4511539669368912*" OR All_Traffic.url="*o4511539639222272.ingest.de.sentry.io/api/4511539669368912/envelope*") by All_Traffic.src All_Traffic.dest All_Traffic.user All_Traffic.process | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// onering crate Sentry C2 — exact org/project from article
let OneringSentryHost = "o4511539639222272.ingest.de.sentry.io";
let OneringProjectId = "4511539669368912";
union isfuzzy=true
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has OneringSentryHost or RemoteUrl has OneringProjectId
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, EventTable="DeviceNetworkEvents"),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has OneringSentryHost or RemoteUrl has OneringSentryHost
  | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort=int(null), EventTable="DeviceEvents-DNS")
| order by Timestamp desc
```

### Cargo build-script-build spawning curl/PowerShell to Sentry envelope endpoint

`UC_120_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name="build-script-build*" OR Processes.parent_process="*\\target\\*\\build\\*build-script-build*" OR Processes.parent_process="*/target/*/build/*build-script-build*") (Processes.process_name IN ("curl.exe","curl","powershell.exe","pwsh.exe","wget","wget.exe")) (Processes.process="*sentry.io*" OR Processes.process="*x-sentry-envelope*" OR Processes.process="*ingest.de.sentry.io*" OR Processes.process="*4511539669368912*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// onering build.rs payload: build-script-build -> curl POST envelope
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName matches regex @"(?i)^build[-_]script[-_]build(\.exe)?$"
      or InitiatingProcessFolderPath matches regex @"(?i)[\\/]target[\\/](debug|release)[\\/]build[\\/].+[\\/]build[-_]script[-_]build")
| where FileName in~ ("curl.exe","curl","powershell.exe","pwsh.exe","wget.exe","wget")
| where ProcessCommandLine has_any ("sentry.io","x-sentry-envelope","ingest.de.sentry.io","4511539669368912","8197ee42c4f59c83f4cc6d48f5bae821","o4511539639222272")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Cargo manifest / lockfile references onering crate

`UC_120_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("cargo.exe","cargo","rustc.exe","rustc") AND (Processes.process="*onering*" OR Processes.process="*1.4.1*onering*" OR Processes.process="*onering*1.4.1*")) OR (Processes.process_name IN ("git.exe","git") AND Processes.process="*github.com/cenotelie/onering*") by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`

| append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("Cargo.toml","Cargo.lock")) by host Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | search file_path="*onering*" OR file_path="*" ]
```

**Defender KQL:**
```kql
// Hunt for onering 1.4.1 ingestion via Cargo or git clone
let OneringStrings = dynamic(["onering","cenotelie/onering"]);
let ProcSignals = DeviceProcessEvents
  | where Timestamp > ago(90d)
  | where (FileName in~ ("cargo.exe","cargo","rustc.exe","rustc") and ProcessCommandLine has_any (OneringStrings))
       or (FileName in~ ("git.exe","git") and ProcessCommandLine has "cenotelie/onering")
       or (ProcessCommandLine has "cargo add" and ProcessCommandLine has "onering")
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, EvidenceType="ProcessCmdline";
let FileSignals = DeviceFileEvents
  | where Timestamp > ago(90d)
  | where FileName in~ ("Cargo.toml","Cargo.lock")
  | where InitiatingProcessFileName in~ ("cargo.exe","cargo","code.exe","rust-analyzer.exe","rust-analyzer","git.exe","git")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=FolderPath, InitiatingProcessFileName, EvidenceType="CargoManifestWrite";
union ProcSignals, FileSignals
| order by Timestamp desc
```

### Cargo build script harvesting git log/diff (onering build.rs payload)

`UC_120_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("git.exe","git") (Processes.parent_process_name="build-script-build*" OR Processes.parent_process="*\\target\\*\\build\\*build-script-build*" OR Processes.parent_process="*/target/*/build/*build-script-build*" OR Processes.parent_process_name="build_script_build*") (Processes.process="*diff HEAD^ HEAD*" OR Processes.process="*--pretty=format:{\"commit\"*" OR Processes.process="*log -n 1*--pretty*") by host Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// onering build.rs: build-script-build -> git log/diff harvest
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","git")
| where InitiatingProcessFileName matches regex @"(?i)^build[-_]script[-_]build(\.exe)?$"
     or InitiatingProcessFolderPath matches regex @"(?i)[\\/]target[\\/](debug|release)[\\/]build[\\/].+[\\/]build[-_]script[-_]build"
| where ProcessCommandLine has_any ("diff HEAD^ HEAD", "--pretty=format:{\"commit\"", "log -n 1")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
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
