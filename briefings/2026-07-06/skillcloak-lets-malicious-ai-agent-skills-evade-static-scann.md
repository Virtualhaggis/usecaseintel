# [HIGH] SkillCloak Lets Malicious AI Agent Skills Evade Static Scanners with Self-Extracting Packing

**Source:** The Hacker News
**Published:** 2026-07-06
**Article:** https://thehackernews.com/2026/07/new-skillcloak-technique-lets-malicious.html

## Threat Profile

SkillCloak Lets Malicious AI Agent Skills Evade Static Scanners with Self-Extracting Packing 
 Swati Khandelwal  Jul 06, 2026 AI Security / Threat Detection 
Scanners meant to catch malicious add-on "skills" for AI coding agents can be fooled by a few simple changes that leave the malware working, according to a  new study  from researchers at the Hong Kong University of Science and Technology.
Their strongest trick slipped past every scanner tested more than 90% of the time, and the same team…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.92.242.30`
- **IPv4 (defanged):** `2.26.75.16`
- **Domain (defanged):** `laosji.net`
- **Domain (defanged):** `letssendit.fun`
- **Domain (defanged):** `download.setup-service.com`
- **Domain (defanged):** `install.app-distribution.net`
- **Domain (defanged):** `openclawcli.vercel.app`
- **SHA256:** `818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7`
- **SHA256:** `b6c7e0bf573b1c7d9d3a05eb08d26579199515b847df984862805f44a7af8007`
- **SHA256:** `b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2`
- **SHA256:** `ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d`
- **SHA256:** `f4e41aa269c88bf11a2022701a9cf41e9a186aa1b224d837c31bf34e0b875d0e`
- **SHA256:** `881ce5cb124c4d2e814783724cc1388f6a1cbf6eee274c3f3366e77ba3503ad7`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1195.001** — Supply Chain Compromise: Compromised Software Dependencies and Development Tools
- **T1564** — Hide Artifacts
- **T1071.004** — Application Layer Protocol: DNS
- **T1105** — Ingress Tool Transfer
- **T1552** — Unsecured Credentials
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1571** — Non-Standard Port

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AI coding-agent detonates payload from scanner-skipped .git/ directory (SkillCloak SFS packing)

`UC_51_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","claude.exe","python.exe","python3.exe","codex.exe","openclaw.exe","bash.exe","sh.exe","cmd.exe","powershell.exe","pwsh.exe")) AND (Processes.process="*\\.git\\*" OR Processes.process="*/.git/*" OR Processes.process_path="*\\.git\\*" OR Processes.process_path="*/.git/*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (FolderPath has @"\.git\" or ProcessCommandLine has @"\.git\" or ProcessCommandLine has "/.git/")
| where InitiatingProcessFileName has_any ("node.exe","claude.exe","python.exe","python3.exe","codex.exe","openclaw.exe","bash.exe","sh.exe","cmd.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Poisoned-repo runtime payload fetch via DNS TXT record by AI coding agent (0DIN axiom chain)

`UC_51_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","claude.exe","python.exe","python3.exe","codex.exe","openclaw.exe","bash.exe","sh.exe")) AND (Processes.process="*axiom init*" OR (Processes.process_name="nslookup.exe" AND (Processes.process="*-type=txt*" OR Processes.process="*-q=txt*" OR Processes.process="*-querytype=txt*")) OR (Processes.process="*Resolve-DnsName*" AND Processes.process="*TXT*") OR (Processes.process_name IN ("dig","dig.exe") AND Processes.process="*txt*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName has_any ("node.exe","claude.exe","python.exe","python3.exe","codex.exe","openclaw.exe","bash.exe","sh.exe")
| where ProcessCommandLine has "axiom init"
    or (FileName =~ "nslookup.exe" and ProcessCommandLine has_any ("-type=txt","-q=txt","-querytype=txt"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Resolve-DnsName" and ProcessCommandLine has "TXT")
    or (FileName =~ "dig.exe" and ProcessCommandLine has "txt")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### AI coding agent spawns reverse shell referencing cloud/AI secret env vars

`UC_51_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","claude.exe","python.exe","python3.exe","codex.exe","openclaw.exe")) AND (Processes.process_name IN ("bash.exe","sh.exe","cmd.exe","powershell.exe","pwsh.exe","nc.exe","ncat.exe")) AND (Processes.process="*ANTHROPIC_API_KEY*" OR Processes.process="*AWS_SECRET_ACCESS_KEY*" OR Processes.process="*GITHUB_TOKEN*" OR Processes.process="*/dev/tcp/*" OR Processes.process="*-e /bin/sh*" OR Processes.process="*-e /bin/bash*" OR Processes.process="*bash -i*" OR Processes.process="*Net.Sockets.TCPClient*" OR Processes.process="*socket.socket*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName has_any ("node.exe","claude.exe","python.exe","python3.exe","codex.exe","openclaw.exe")
| where FileName in~ ("bash.exe","sh.exe","cmd.exe","powershell.exe","pwsh.exe","nc.exe","ncat.exe")
| where ProcessCommandLine has_any ("ANTHROPIC_API_KEY","AWS_SECRET_ACCESS_KEY","GITHUB_TOKEN","/dev/tcp/","-e /bin/sh","-e /bin/bash","bash -i","Net.Sockets.TCPClient","socket.socket")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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
  - IP / domain IOC(s): `91.92.242.30`, `2.26.75.16`, `laosji.net`, `letssendit.fun`, `download.setup-service.com`, `install.app-distribution.net`, `openclawcli.vercel.app`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7`, `b6c7e0bf573b1c7d9d3a05eb08d26579199515b847df984862805f44a7af8007`, `b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2`, `ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d`, `f4e41aa269c88bf11a2022701a9cf41e9a186aa1b224d837c31bf34e0b875d0e`, `881ce5cb124c4d2e814783724cc1388f6a1cbf6eee274c3f3366e77ba3503ad7`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
