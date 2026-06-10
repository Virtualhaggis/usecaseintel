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
- **T1059** — Command and Scripting Interpreter
- **T1213.003** — Code Repositories
- **T1071.001** — Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### DNS/URL egress to malicious onering Sentry org subdomain (o4511539639222272)

`UC_15_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.url) as urls values(Network_Traffic.app) as apps from datamodel=Network_Traffic.All_Traffic where (Network_Traffic.dest_host="o4511539639222272.ingest.de.sentry.io" OR Network_Traffic.url="*o4511539639222272.ingest.de.sentry.io*" OR Network_Traffic.url="*8197ee42c4f59c83f4cc6d48f5bae821*" OR Network_Traffic.url="*4511539669368912/envelope*") by Network_Traffic.src host Network_Traffic.user Network_Traffic.dest_host Network_Traffic.dest | `drop_dm_object_name(Network_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// onering 1.4.1 hard-codes this Sentry org+project — both IDs are attacker-unique
let IocHost = "o4511539639222272.ingest.de.sentry.io";
let IocDsn  = "8197ee42c4f59c83f4cc6d48f5bae821";
let IocProj = "4511539669368912/envelope";
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (IocHost, IocDsn, IocProj)
   or AdditionalFields has_any (IocHost, IocDsn, IocProj)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### git diff HEAD^ HEAD spawned by Rust cargo build script (onering source-code collection)

`UC_15_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parent_cmds from datamodel=Endpoint.Processes where Processes.process_name IN ("git.exe","git") AND (Processes.process="*diff HEAD^ HEAD*" OR Processes.process="*-n 1 --pretty=format*" OR Processes.process="*\"commit\":\"%H\"*") AND (Processes.parent_process_name IN ("build-script-build.exe","build_script_build.exe","build-script-build","cargo.exe","rustc.exe") OR Processes.parent_process="*\\target\\debug\\build\\*" OR Processes.parent_process="*\\target\\release\\build\\*" OR Processes.parent_process="*/target/debug/build/*" OR Processes.parent_process="*/target/release/build/*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// onering 1.4.1 build.rs runs: git log -n 1 --pretty=format:{...} AND git diff HEAD^ HEAD
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("git.exe","git")
| where ProcessCommandLine has_any ("diff HEAD^ HEAD",
                                    @'--pretty=format:{"commit":"%H"',
                                    "-n 1 --pretty=format")
| where InitiatingProcessFileName matches regex @"(?i)^(build[-_]script[-_]build(\.exe)?|cargo(\.exe)?|rustc(\.exe)?)$"
    or InitiatingProcessFolderPath has @"\target\debug\build\"
    or InitiatingProcessFolderPath has @"\target\release\build\"
    or InitiatingProcessFolderPath matches regex @"(?i)/target/(debug|release)/build/"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### curl POSTing application/x-sentry-envelope from Rust cargo build tree (onering exfil)

`UC_15_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parent_cmds from datamodel=Endpoint.Processes where Processes.process_name IN ("curl.exe","curl") AND (Processes.process="*application/x-sentry-envelope*" OR Processes.process="*ingest.de.sentry.io*" OR Processes.process="*/envelope/*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | search (parent_process="*build-script-build*" OR parent_process="*\\cargo.exe*" OR parent_process="*\\rustc.exe*" OR parent_process="*\\target\\debug\\build\\*" OR parent_process="*\\target\\release\\build\\*" OR parent_process="*/target/debug/build/*" OR parent_process="*/target/release/build/*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("curl.exe","curl")
| where ProcessCommandLine has_any ("application/x-sentry-envelope",
                                    "ingest.de.sentry.io",
                                    "/envelope/",
                                    "o4511539639222272",
                                    "8197ee42c4f59c83f4cc6d48f5bae821")
| where InitiatingProcessFileName matches regex @"(?i)^(build[-_]script[-_]build(\.exe)?|cargo(\.exe)?|rustc(\.exe)?)$"
    or InitiatingProcessFolderPath has @"\target\debug\build\"
    or InitiatingProcessFolderPath has @"\target\release\build\"
    or InitiatingProcessFolderPath matches regex @"(?i)/target/(debug|release)/build/"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SHA256
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

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
