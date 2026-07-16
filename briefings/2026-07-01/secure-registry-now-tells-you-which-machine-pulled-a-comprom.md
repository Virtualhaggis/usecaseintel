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
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1070.004** — Indicator Removal: File Deletion
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### easy-day-js second-stage C2 beacon to Mastra supply-chain infrastructure

`UC_175_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="23.254.164.92" OR All_Traffic.dest_ip="23.254.164.123" OR All_Traffic.dest="teams.onweblive.org" OR All_Traffic.dest="maskasd.com") by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("23.254.164.92", "23.254.164.123") or RemoteUrl in~ ("teams.onweblive.org", "maskasd.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### npm/node postinstall script spawning a download or shell process (Mastra dropper pattern)

`UC_175_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd") Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe","curl.exe","certutil.exe","bitsadmin.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | search (parent_process="*node_modules*" OR process="*http*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "npm.exe", "npm.cmd")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "cscript.exe", "wscript.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "bash.exe", "wget.exe")
| where InitiatingProcessCommandLine has "node_modules" or InitiatingProcessCommandLine has "postinstall" or ProcessCommandLine has_any ("http://", "https://")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Malicious easy-day-js typosquat package written into node_modules

`UC_175_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*easy-day-js*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "easy-day-js"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Package-manager dropper self-deletion inside node_modules (evidence erasure)

`UC_175_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action="deleted" Filesystem.process_name IN ("node.exe","npm.exe") Filesystem.file_path="*node_modules*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileDeleted"
| where InitiatingProcessFileName in~ ("node.exe", "npm.exe")
| where FolderPath has "node_modules"
| where FileName endswith ".js" or FileName endswith ".cjs" or FileName endswith ".sh"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

### Known-malicious Mastra supply-chain payload file hashes on disk or in execution

`UC_175_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4","ae70dd4f6bc0d1c8c2848e4e6b51934626c4818dcb5af99d080ddbd7dc337185","4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417","b73de25c053c3225a077738a1fcbd9ca6966d7b3cd6f5494a30f0aa0eae55c7e","221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf","6b9501e1889cc45c91726729610cf69c2442b8c5")) by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in ("b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4", "ae70dd4f6bc0d1c8c2848e4e6b51934626c4818dcb5af99d080ddbd7dc337185", "4a8860240e4231c3a74c81949be655a28e096a7d72f38fbe84e5b37636b98417", "b73de25c053c3225a077738a1fcbd9ca6966d7b3cd6f5494a30f0aa0eae55c7e", "221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf")
    or SHA1 == "6b9501e1889cc45c91726729610cf69c2442b8c5"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, SHA1, InitiatingProcessCommandLine
| order by Timestamp desc
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
