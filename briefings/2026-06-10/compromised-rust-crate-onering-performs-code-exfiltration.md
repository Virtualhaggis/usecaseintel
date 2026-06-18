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
- **T1071.001** — Web Protocols
- **T1005** — Data from Local System
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.004** — Unix Shell
- **T1041** — Exfiltration Over C2 Channel
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound POST to onering Sentry exfil endpoint (o4511539639222272.ingest.de.sentry.io)

`UC_124_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.user) as user values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="o4511539639222272.ingest.de.sentry.io" OR All_Traffic.url="*o4511539639222272.ingest.de.sentry.io*" OR All_Traffic.url="*4511539669368912/envelope*" OR All_Traffic.url="*8197ee42c4f59c83f4cc6d48f5bae821*" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("o4511539639222272.ingest.de.sentry.io", "4511539669368912/envelope", "8197ee42c4f59c83f4cc6d48f5bae821")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Cargo build-time git log/diff exfil pattern (onering build.rs)

`UC_124_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("git","git.exe") AND Processes.parent_process_name IN ("cargo","cargo.exe","rustc","rustc.exe","build-script-build","build-script-build.exe") AND (Processes.process="*diff HEAD^ HEAD*" OR Processes.process="*log -n 1*--pretty=format*commit*author*email*date*subject*") by host Processes.dest Processes.parent_process_name Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","git")
| where InitiatingProcessFileName in~ ("cargo.exe","cargo","rustc.exe","rustc","build-script-build.exe","build-script-build")
| where ProcessCommandLine has_any ("diff HEAD^ HEAD", "diff HEAD~1 HEAD")
   or (ProcessCommandLine has "log" and ProcessCommandLine has "-n 1" and ProcessCommandLine has "--pretty=format" and ProcessCommandLine has "%H" and ProcessCommandLine has "%an")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### curl/wget POST with Sentry envelope Content-Type spawned by build script

`UC_124_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("curl","curl.exe","wget","wget.exe") AND (Processes.process="*application/x-sentry-envelope*" OR Processes.process="*ingest.de.sentry.io/api/*/envelope*" OR Processes.process="*4511539669368912/envelope*") by host Processes.dest Processes.parent_process_name Processes.process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("application/x-sentry-envelope","ingest.de.sentry.io/api/","/envelope/")
| where InitiatingProcessFileName in~ ("cargo.exe","cargo","rustc.exe","rustc","build-script-build.exe","build-script-build")
   or InitiatingProcessParentFileName in~ ("cargo.exe","cargo","rustc.exe","rustc","build-script-build.exe","build-script-build")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Cargo/rustc build script spawning network or git utilities (build.rs LOLBin abuse)

`UC_124_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("build-script-build","build-script-build.exe","cargo","cargo.exe","rustc","rustc.exe") AND Processes.process_name IN ("curl","curl.exe","wget","wget.exe","powershell.exe","pwsh.exe","cmd.exe","bash","sh","git","git.exe","nslookup.exe","certutil.exe","bitsadmin.exe") by host Processes.dest Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(cmdline,"(?i)(rustc|--version|--print|cargo|linker|cc1|ld\.exe|link\.exe|lld)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let BaselineDays = 30d;
let RecentHours = 24h;
let Baseline = DeviceProcessEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | where InitiatingProcessFileName in~ ("build-script-build.exe","build-script-build","cargo.exe","cargo","rustc.exe","rustc")
    | summarize by DeviceName, InitiatingProcessFileName, FileName;
DeviceProcessEvents
| where Timestamp > ago(RecentHours)
| where InitiatingProcessFileName in~ ("build-script-build.exe","build-script-build","cargo.exe","cargo","rustc.exe","rustc")
| where FileName in~ ("curl.exe","curl","wget.exe","wget","powershell.exe","pwsh.exe","cmd.exe","bash","sh","git.exe","git","nslookup.exe","certutil.exe","bitsadmin.exe")
| where AccountName !endswith "$"
| join kind=leftanti Baseline on DeviceName, InitiatingProcessFileName, FileName
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
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

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
