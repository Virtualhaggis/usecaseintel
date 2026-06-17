# [MED] FishMonger’s arsenal upgraded: SprySOCKS for Windows

**Source:** ESET WeLiveSecurity
**Published:** 2026-06-16
**Article:** https://www.welivesecurity.com/en/eset-research/fishmongers-arsenal-upgraded-sprysocks-windows/

## Threat Profile

ESET researchers have discovered two as-yet undocumented Windows variants of SprySOCKS , a previously Linux-only backdoor reportedly used by FishMonger, the group believed to be operated by a Chinese contractor named I‑SOON. While we initially discovered the malware samples on VirusTotal, ESET telemetry shows real activity between 2023 and 2024, with several victims in Honduras, Taiwan, Thailand, and Pakistan, targeting mostly government organizations.
The Windows variants discovered are interna…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-24932`
- **IPv4 (defanged):** `207.148.78.36`
- **IPv4 (defanged):** `207.148.75.122`
- **SHA1:** `955BFC3DCC867256F9F46A606DEB0779FA3416D8`
- **SHA1:** `44DC4A08C5EB0972C8E18B0E01284E06F09006BB`
- **SHA1:** `AB87B29B6F79487C75CA08D102E79001E536F083`
- **SHA1:** `6490B8E4AADE25A3EE2DA9A47F312DB2122470BC`
- **SHA1:** `E7484C24B88A1A2407A8F09D734F9A993670285B`
- **SHA1:** `621D1952839BE4B0A1B0E66E87BCE5062CA368ED`
- **SHA1:** `2457EED2AB28E37741F10914EF929DAD2C8079D4`
- **SHA1:** `D2C706B1EAF662BF0CE124B5032F73ED84BDA24A`
- **SHA1:** `5F3B87CEF56683D9A9E19186E0FD0D8019B559C4`
- **SHA1:** `C793CA31E3F6628B5C8986146953BF66232E9A30`
- **SHA1:** `037DB2445F3D72388CB2CF8510563148E5A184BE`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1014** — Rootkit
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1553.006** — Subvert Trust Controls: Code Signing Policy Modification
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1573** — Encrypted Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SprySOCKS WIN_DRV/WIN_PLUS C2 beacon to FishMonger Vultr infra

`UC_37_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.src) as src values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("207.148.78.36","207.148.75.122") by All_Traffic.src All_Traffic.dest All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("207.148.78.36","207.148.75.122")
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA1, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### SprySOCKS WIN_DRV/WIN_PLUS sample execution by published SHA1

`UC_37_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_sha1 in ("955BFC3DCC867256F9F46A606DEB0779FA3416D8","44DC4A08C5EB0972C8E18B0E01284E06F09006BB","AB87B29B6F79487C75CA08D102E79001E536F083","6490B8E4AADE25A3EE2DA9A47F312DB2122470BC","E7484C24B88A1A2407A8F09D734F9A993670285B","621D1952839BE4B0A1B0E66E87BCE5062CA368ED","2457EED2AB28E37741F10914EF929DAD2C8079D4","D2C706B1EAF662BF0CE124B5032F73ED84BDA24A","5F3B87CEF56683D9A9E19186E0FD0D8019B559C4","C793CA31E3F6628B5C8986146953BF66232E9A30","037DB2445F3D72388CB2CF8510563148E5A184BE") by Processes.dest Processes.process_sha1 Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let SprySOCKSHashes = dynamic(["955BFC3DCC867256F9F46A606DEB0779FA3416D8","44DC4A08C5EB0972C8E18B0E01284E06F09006BB","AB87B29B6F79487C75CA08D102E79001E536F083","6490B8E4AADE25A3EE2DA9A47F312DB2122470BC","E7484C24B88A1A2407A8F09D734F9A993670285B","621D1952839BE4B0A1B0E66E87BCE5062CA368ED","2457EED2AB28E37741F10914EF929DAD2C8079D4","D2C706B1EAF662BF0CE124B5032F73ED84BDA24A","5F3B87CEF56683D9A9E19186E0FD0D8019B559C4","C793CA31E3F6628B5C8986146953BF66232E9A30","037DB2445F3D72388CB2CF8510563148E5A184BE"]);
union
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA1 in (SprySOCKSHashes)
    | project Timestamp, Source="ProcessExec", DeviceName, AccountName, FileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA1 in (SprySOCKSHashes)
    | project Timestamp, Source="FileWrite", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA1 in (SprySOCKSHashes)
    | project Timestamp, Source="ImageLoad", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName)
| order by Timestamp desc
```

### SprySOCKS WIN_DRV kernel rootkit service install with TCP traffic-diversion driver

`UC_37_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as svc_image values(Registry.user) as user from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentControlSet\\Services\\*\\ImagePath" Registry.registry_value_data IN ("*\\Temp\\*.sys","*\\AppData\\*.sys","*\\ProgramData\\*.sys","*\\PerfLogs\\*.sys","*\\Users\\Public\\*.sys") by Registry.dest Registry.registry_key_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentControlSet\Services"
| where RegistryValueName in~ ("ImagePath","ServiceDll")
| where RegistryValueData endswith ".sys"
| where RegistryValueData has_any (@"\Temp\", @"\AppData\", @"\ProgramData\", @"\PerfLogs\", @"\Users\Public\", @"\Windows\Tasks\")
      or RegistryValueData matches regex @"\\[a-z0-9]{6,10}\.sys$"
| where InitiatingProcessFileName !in~ ("msiexec.exe","trustedinstaller.exe","setup.exe","vmms.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### SprySOCKS bootkit precursor — CVE-2023-24932 BCD / ESP tampering

`UC_37_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("bcdedit.exe","mountvol.exe","bootsect.exe") AND (Processes.process="*EFI*" OR Processes.process="*bootmgr*" OR Processes.process="*{bootmgr}*" OR Processes.process="*{fwbootmgr}*" OR Processes.process="*/s:*")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
  (DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("bcdedit.exe","mountvol.exe","bootsect.exe")
    | where ProcessCommandLine has_any ("EFI","bootmgr","{bootmgr}","{fwbootmgr}","/set","/store","/s:")
    | where AccountName !endswith "$"
    | project Timestamp, Kind="BootCfgCmd", DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath),
  (DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath has @"\EFI\Microsoft\Boot\"
        or FolderPath has @"\EFI\Boot\"
        or FileName in~ ("bootmgfw.efi","bootmgr.efi","winload.efi")
    | where InitiatingProcessFileName !in~ ("trustedinstaller.exe","wuauclt.exe","poqexec.exe","tiworker.exe")
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, Kind="ESPWrite", DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath)
| order by Timestamp desc
```

### SprySOCKS WebSocket C2 — long-lived HTTP/1.1 Upgrade to non-CDN endpoint

`UC_37_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.dest) as dest values(Web.http_user_agent) as ua values(Web.bytes_out) as bytes_out from datamodel=Web.Web where Web.http_method="GET" Web.url="*Upgrade*websocket*" OR Web.http_user_agent="*websocket*" by Web.src Web.user Web.app | `drop_dm_object_name(Web)` | where NOT match(dest, "(?i)(slack\.com|teams\.microsoft\.com|signalr\.net|pusher\.com|hotjar\.com|intercom\.io|live\.com|googleapis\.com|amazonaws\.com|cloudfront\.net|zoom\.us|akamaihd\.net|cloudflare\.com)$")
```

**Defender KQL:**
```kql
let BrowserBins = dynamic(["msedge.exe","chrome.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","WindowsTerminal.exe","Code.exe","slack.exe","teams.exe","ms-teams.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where Protocol == "Tcp"
| where RemotePort in (80, 8080, 8000, 8888, 81, 443, 8443) or RemotePort between (1024 .. 65535)
| where InitiatingProcessFileName !in~ (BrowserBins)
| where InitiatingProcessFolderPath !startswith @"C:\Program Files\"
      and InitiatingProcessFolderPath !startswith @"C:\Program Files (x86)\"
      and InitiatingProcessFolderPath !startswith @"C:\Windows\System32\"
      and InitiatingProcessFolderPath !startswith @"C:\Windows\SysWOW64\"
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnCount = count(), Bytes = countif(ActionType=="ConnectionSuccess"), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Ports = make_set(RemotePort, 25), Hosts = dcount(DeviceName) by InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP
| where ConnCount >= 5 and (LastSeen - FirstSeen) > 10m
| order by LastSeen desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-24932`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `207.148.78.36`, `207.148.75.122`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `955BFC3DCC867256F9F46A606DEB0779FA3416D8`, `44DC4A08C5EB0972C8E18B0E01284E06F09006BB`, `AB87B29B6F79487C75CA08D102E79001E536F083`, `6490B8E4AADE25A3EE2DA9A47F312DB2122470BC`, `E7484C24B88A1A2407A8F09D734F9A993670285B`, `621D1952839BE4B0A1B0E66E87BCE5062CA368ED`, `2457EED2AB28E37741F10914EF929DAD2C8079D4`, `D2C706B1EAF662BF0CE124B5032F73ED84BDA24A` _(+3 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
