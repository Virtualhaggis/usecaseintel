# [CRIT] Secure Registry now tells you which machine pulled a compromised package

**Source:** StepSecurity
**Published:** 2026-07-01
**Article:** https://www.stepsecurity.io/blog/secure-registry-now-tells-you-which-machine-pulled-a-compromised-package

## Threat Profile

Back to Blog Product Secure Registry now tells you which machine pulled a compromised package Secure Registry now traces every npm and PyPI install back to the developer machine or CI pipeline behind it, so you can scope a compromised package in minutes. Sai Likhith View LinkedIn June 26, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
On June 17, 2026, an attacker compromised the @mastra npm organization and quietly added eas…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.254.164.92`
- **IPv4 (defanged):** `23.254.164.123`
- **Domain (defanged):** `teams.onweblive.org`
- **Domain (defanged):** `maskasd.com`
- **SHA256:** `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`
- **SHA256:** `ae70dd4f6bc0d1c8c2848e4e6b51934626c4818dcb5af99d080ddbd7dc337185`
- **SHA256:** `4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417`
- **SHA256:** `b73de25c053c3225a077738a1fcbd9ca6966d7b3cd6f5494a30f0aa0eae55c7e`
- **SHA256:** `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`
- **SHA1:** `6b9501e1889cc45c91726729610cf69c2442b8c5`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1195.001** — Compromised Software Dependencies and Development Tools
- **T1195.002** — Compromised Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1070.004** — Indicator Removal: File Deletion
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Machine that pulled compromised easy-day-js npm package (node_modules write)

`UC_29_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\node_modules\\easy-day-js\\*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\node_modules\easy-day-js\"
| where InitiatingProcessFileName has_any ("node.exe","npm.cmd","npm.exe","npx.cmd","pnpm.exe","yarn.exe","node")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Files=make_set(FileName, 20), any(SHA256) by DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath
| order by LastSeen desc
```

### easy-day-js dropper C2 beacon to Sapphire Sleet Hostwinds infrastructure

`UC_29_5` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("23.254.164.92","23.254.164.123") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("23.254.164.92","23.254.164.123")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### easy-day-js self-deleting postinstall dropper temp artifacts (.pkg_history/.pkg_logs)

`UC_29_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".pkg_history" OR Filesystem.file_name=".pkg_logs") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (".pkg_history",".pkg_logs")
| where InitiatingProcessFileName has_any ("node.exe","npm.cmd","npm.exe","pnpm.exe","yarn.exe","node")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### easy-day-js second-stage infostealer reading browser secrets & crypto-wallet extensions via node

`UC_29_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name="node.exe" OR Filesystem.process_name="node") AND (Filesystem.file_name IN ("Login Data","Local State","Cookies","Web Data") OR Filesystem.file_path="*Local Extension Settings*") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "node.exe"
| where (FileName in~ ("Login Data","Local State","Cookies","Web Data"))
     or FolderPath has_any (@"\User Data\Default\Local Extension Settings", "Local Extension Settings", @"\Mozilla\Firefox\Profiles")
| where FolderPath has_any (@"\Google\Chrome\", @"\Microsoft\Edge\", @"\BraveSoftware\", @"\Mozilla\Firefox\", @"\Chromium\")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Targets=make_set(FolderPath, 30) by DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by LastSeen desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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
  - IP / domain IOC(s): `23.254.164.92`, `23.254.164.123`, `teams.onweblive.org`, `maskasd.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`, `ae70dd4f6bc0d1c8c2848e4e6b51934626c4818dcb5af99d080ddbd7dc337185`, `4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417`, `b73de25c053c3225a077738a1fcbd9ca6966d7b3cd6f5494a30f0aa0eae55c7e`, `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`, `6b9501e1889cc45c91726729610cf69c2442b8c5`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
