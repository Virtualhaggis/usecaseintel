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
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer
- **T1005** — Data from Local System
- **T1195.001** — Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound POST to onering crate C2 Sentry ingest endpoint (o4511539639222272.ingest.de.sentry.io)

`UC_161_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.user) as users from datamodel=Web where Web.url="*o4511539639222272.ingest.de.sentry.io*" OR Web.url="*4511539669368912/envelope*" OR Web.url="*8197ee42c4f59c83f4cc6d48f5bae821*" by Web.src Web.dest host | `drop_dm_object_name("Web")` | append [| tstats summariesonly=t count from datamodel=Network_Traffic where All_Traffic.dest="o4511539639222272.ingest.de.sentry.io" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "o4511539639222272.ingest.de.sentry.io"
   or RemoteUrl has "4511539669368912/envelope"
   or RemoteUrl has "8197ee42c4f59c83f4cc6d48f5bae821"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### curl POSTing Sentry envelope payload from cargo/build-script-build context

`UC_161_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_name="curl.exe" OR Processes.process_name="curl") AND (Processes.process="*o4511539639222272.ingest.de.sentry.io*" OR Processes.process="*4511539669368912/envelope*" OR Processes.process="*8197ee42c4f59c83f4cc6d48f5bae821*" OR Processes.process="*application/x-sentry-envelope*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name("Processes")`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe","curl")
| where ProcessCommandLine has_any (
    "o4511539639222272.ingest.de.sentry.io",
    "4511539669368912/envelope",
    "8197ee42c4f59c83f4cc6d48f5bae821",
    "application/x-sentry-envelope"
  )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          ParentImage=InitiatingProcessFolderPath,
          ParentName=InitiatingProcessFileName,
          ParentCmd=InitiatingProcessCommandLine,
          GrandparentName=InitiatingProcessParentFileName
| order by Timestamp desc
```

### Rust build script (build-script-build) executing 'git diff HEAD^ HEAD' for source-code harvesting

`UC_161_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where (Processes.process_name="git.exe" OR Processes.process_name="git") AND Processes.process="*diff*" AND Processes.process="*HEAD^*" AND Processes.process="*HEAD*" AND (Processes.parent_process_name="build-script-build*" OR Processes.parent_process_name="build_script_build*" OR Processes.parent_process_name="build-script-main*" OR Processes.parent_process="*\\target\\debug\\build\\*" OR Processes.parent_process="*/target/debug/build/*" OR Processes.parent_process="*\\target\\release\\build\\*" OR Processes.parent_process="*/target/release/build/*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name("Processes")`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("git.exe","git")
| where ProcessCommandLine has "diff"
| where ProcessCommandLine has "HEAD^" or ProcessCommandLine matches regex @"HEAD\^?\s+HEAD"
| where InitiatingProcessFileName startswith "build-script-"
     or InitiatingProcessFileName startswith "build_script_"
     or InitiatingProcessFolderPath has @"\target\debug\build\"
     or InitiatingProcessFolderPath has "/target/debug/build/"
     or InitiatingProcessFolderPath has @"\target\release\build\"
     or InitiatingProcessFolderPath has "/target/release/build/"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine,
          GrandparentName=InitiatingProcessParentFileName
| order by Timestamp desc
```

### onering 1.4.1 crate landing in cargo registry cache (compromised-version install)

`UC_161_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.cargo\\registry\\*onering-1.4.1*" OR Filesystem.file_path="*/.cargo/registry/*onering-1.4.1*" OR Filesystem.file_name="onering-1.4.1.crate") AND Filesystem.action="created" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name("Filesystem")`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\.cargo\registry\" or FolderPath has "/.cargo/registry/")
| where (FileName == "onering-1.4.1.crate")
     or (FolderPath has "onering-1.4.1" and FileName in~ ("build.rs","Cargo.toml","lib.rs"))
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
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
