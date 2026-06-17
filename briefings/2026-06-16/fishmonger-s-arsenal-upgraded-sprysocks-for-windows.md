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
- **T1068** — Exploitation for Privilege Escalation
- **T1059** — Command and Scripting Interpreter
- **T1204.002** — User Execution: Malicious File
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1547.001** — Boot or Logon Autostart Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SprySOCKS Windows C2 egress to FishMonger infrastructure 207.148.78.36 / 207.148.75.122

`UC_49_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as process from datamodel=Network_Traffic where All_Traffic.dest in ("207.148.78.36","207.148.75.122") by All_Traffic.dest All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("207.148.78.36", "207.148.75.122")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, Protocol, InitiatingProcessAccountName
| order by Timestamp desc
```

### WIN_DRV kernel driver service installed from non-system path

`UC_49_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Services.service_path) as service_path values(All_Services.service_name) as service_name values(All_Services.user) as user from datamodel=Endpoint.Services where All_Services.service_type="kernel*" AND NOT (All_Services.service_path IN ("*\\Windows\\System32\\drivers\\*","*\\Windows\\SysWOW64\\drivers\\*","*\\Windows\\System32\\DriverStore\\*")) by All_Services.dest All_Services.service_path All_Services.service_name | `drop_dm_object_name(All_Services)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("DriverLoad", "ServiceInstalled")
| where FolderPath !startswith @"C:\Windows\System32\drivers\"
    and FolderPath !startswith @"C:\Windows\SysWOW64\drivers\"
    and FolderPath !startswith @"C:\Windows\System32\DriverStore\"
| where FileName endswith ".sys"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### SprySOCKS WIN_DRV / WIN_PLUS binary hash hit on Windows endpoint

`UC_49_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_sha1 IN ("955BFC3DCC867256F9F46A606DEB0779FA3416D8","44DC4A08C5EB0972C8E18B0E01284E06F09006BB","AB87B29B6F79487C75CA08D102E79001E536F083","6490B8E4AADE25A3EE2DA9A47F312DB2122470BC","E7484C24B88A1A2407A8F09D734F9A993670285B","621D1952839BE4B0A1B0E66E87BCE5062CA368ED","2457EED2AB28E37741F10914EF929DAD2C8079D4","D2C706B1EAF662BF0CE124B5032F73ED84BDA24A","5F3B87CEF56683D9A9E19186E0FD0D8019B559C4","C793CA31E3F6628B5C8986146953BF66232E9A30","037DB2445F3D72388CB2CF8510563148E5A184BE") by Processes.dest Processes.process_sha1 | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let sprysocks_sha1 = dynamic([
    "955BFC3DCC867256F9F46A606DEB0779FA3416D8",
    "44DC4A08C5EB0972C8E18B0E01284E06F09006BB",
    "AB87B29B6F79487C75CA08D102E79001E536F083",
    "6490B8E4AADE25A3EE2DA9A47F312DB2122470BC",
    "E7484C24B88A1A2407A8F09D734F9A993670285B",
    "621D1952839BE4B0A1B0E66E87BCE5062CA368ED",
    "2457EED2AB28E37741F10914EF929DAD2C8079D4",
    "D2C706B1EAF662BF0CE124B5032F73ED84BDA24A",
    "5F3B87CEF56683D9A9E19186E0FD0D8019B559C4",
    "C793CA31E3F6628B5C8986146953BF66232E9A30",
    "037DB2445F3D72388CB2CF8510563148E5A184BE"]);
union isfuzzy=true
    (DeviceProcessEvents
        | where Timestamp > ago(90d)
        | where SHA1 in (sprysocks_sha1)
        | project Timestamp, DeviceName, Event = "ProcessExecution", FileName, FolderPath, SHA1, AccountName, ProcessCommandLine),
    (DeviceFileEvents
        | where Timestamp > ago(90d)
        | where SHA1 in (sprysocks_sha1)
        | project Timestamp, DeviceName, Event = "FileWrite", FileName, FolderPath, SHA1, AccountName = InitiatingProcessAccountName, ProcessCommandLine = InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Boot Manager / BCD tampering indicative of CVE-2023-24932 BlackLotus-style UEFI bootkit

`UC_49_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\EFI\\Microsoft\\Boot\\bootmgfw.efi" OR Filesystem.file_path="*\\EFI\\Boot\\bootx64.efi" OR Filesystem.file_name="bootmgr.efi") AND NOT Filesystem.process_name IN ("TrustedInstaller.exe","wuauserv.exe","WindowsUpdate.exe") by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union isfuzzy=true
    (DeviceFileEvents
        | where Timestamp > ago(30d)
        | where FolderPath has_any (@"\EFI\Microsoft\Boot\", @"\EFI\Boot\")
            or FileName in~ ("bootmgfw.efi", "bootmgr.efi", "bootx64.efi", "winload.efi")
        | where InitiatingProcessFileName !in~ ("TrustedInstaller.exe", "MoUsoCoreWorker.exe", "setup.exe", "BootRec.exe", "bcdboot.exe")
        | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
    (DeviceProcessEvents
        | where Timestamp > ago(30d)
        | where FileName =~ "bcdedit.exe"
        | where ProcessCommandLine has_any ("/set", "/copy", "/create")
        | where ProcessCommandLine has_any ("bootmgr", "path", "description", "{bootmgr}", "nointegritychecks", "testsigning")
        | project Timestamp, DeviceName, ActionType = "BcdeditExec", FileName, FolderPath, SHA256 = "", InitiatingProcessFileName, InitiatingProcessCommandLine = ProcessCommandLine, InitiatingProcessAccountName = AccountName)
| order by Timestamp desc
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

Severity classified as **MED** based on: CVE present, IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
