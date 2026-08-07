# [HIGH] DRILLAPP: new backdoor targeting Ukrainian entities with possible links to Laundry Bear

**Source:** Lab52
**Published:** 2026-03-13
**Article:** https://lab52.io/blog/drillapp-new-backdoor-targeting-ukrainian-entities-with-possible-links-to-laundry-bear/

## Threat Profile

LAB52, the intelligence team at S2 Group, has identified a new campaign targeting Ukrainian entities, attributed to actors linked to Russia. The campaign, observed during February 2026, employs various judicial and charity themed lures to deploy a JavaScript‑based backdoor that runs through the Edge browser and has been named DRILLAPP by LAB52. This artifact enables the attacker to carry out several actions on the target, such as uploading and downloading files, using the microphone, or capturin…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `80.89.224.13`
- **IPv4 (defanged):** `188.137.228.162`
- **Domain (defanged):** `pastefy.app`
- **Domain (defanged):** `short-link.net`
- **Domain (defanged):** `iili.io`
- **SHA256:** `5b978cdc46afa28d83e532cd19622d9097bebedf87efc4c87bd35d8ffad9e672`
- **SHA256:** `6178b1af51057c0bac75a842afff500a8fa3ed957d79a712a6ef089bec7e7a8b`
- **SHA256:** `ac60eefc2607216f8126c0b22b6243f3862ef2bb265c585deee0d00a20a436b3`
- **SHA256:** `e20831cecd763d0dc91fb39f3bd61d17002608c5a40a6cf0bd16111f4e50d341`
- **SHA256:** `ee90b01b16099e0bb23d4653607a3a559590fc8d0c43120b8456fb1860d2e630`
- **SHA256:** `32973ef02e10a585a4a0196b013265e29fc57d8e1c50752f7b39e43b9f388715`
- **SHA256:** `107b2badfc93fcdd3ffda7d3999477ced3f39f43f458dd0f6a424c9ab52681c3`
- **SHA256:** `a545908c931ec47884b5ccfb1f112435f5d0cdac140e664673672c9df9016672`
- **SHA256:** `352f34ea5cc40e2b3ec056ae60fa19a368dbd42503ef225cb1ca57956eb05e81`
- **SHA256:** `c6905bae088982a2b234451b45db742098f2e2ab4fd6ca62c8f4e801160552aa`
- **SHA256:** `993d55f60414bf2092f421c3d0ac6af1897a21cc4ea260ae8e610a402bf4c81c`
- **SHA256:** `ccb7d999ee4d979e175b8c87e09ccda0cbc93b6140471283e3a1f1f9da33759d`
- **SHA256:** `51e86408904c0ca3778361cde746783a0f2b9fd2a6782aa7e062aa597151876e`
- **SHA256:** `fb16933b09a4fcca5beff93da05566e924017fb534a2f45caf57b57a633f43a6`
- **SHA256:** `2b5d8f8db5fd38ae1c34807dcba35b057cffa61eb14ba3b558f82eb630480c3f`
- **SHA256:** `eb9c1649e01db6a9a94d5d50373e54865d672b14ad6f221c98047c562d3cc0f3`
- **SHA256:** `8c6ea44ce7f4ed4e4e7e19e11b3b345d58785c93b33aa795ddd1b0d753236b05`
- **SHA256:** `66a7828bc8c6c783b2ffa3c906d53f6dae1bbddc019283cc369d7d73247c5181`
- **SHA256:** `886df55794cbca146de96dcc626471b3c097a5c20ba488033b24f4347aa20a14`
- **SHA256:** `9367f4b4d2775ff47279d143dd9a0ef544ddff81946aab33da9350a49f14e1e1`
- **SHA256:** `b891fa118db5190f07b18be46eb9bc10677f9afab1406a7d52ce587522ab3d28`
- **SHA256:** `bad7c6f6ca25363a02eaceb3ed1e378218dc4a246a63d723cfcc5feee3af5056`
- **SHA256:** `21fefc3913d3d2dfde7f0dff54800ca7512eb5df9513b1a457a2af25fdd51b26`
- **SHA256:** `801c47550799831bfb1ac6c5c3fd698be95da19fc85bd65f5d8639f26244d2a9`
- **SHA256:** `6fea579685d2433cedb1c32ef704575dcbc1d0a623769e824023ffccd0dedaae`
- **SHA256:** `76eb713e38f145ee68b89f2febd8f9a28bbb2b464da61cb029d84433a0b2c746`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1123** — Audio Capture
- **T1125** — Video Capture
- **T1113** — Screen Capture
- **T1105** — Ingress Tool Transfer
- **T1218** — System Binary Proxy Execution
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1218.002** — System Binary Proxy Execution: Control Panel
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### DRILLAPP: Edge launched headless with media/security guardrails disabled

`UC_610_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="msedge.exe" Processes.process="*--headless*" (Processes.process="*--disable-web-security*" OR Processes.process="*--allow-file-access-from-files*" OR Processes.process="*--use-fake-ui-for-media-stream*" OR Processes.process="*--auto-select-screen-capture-source=true*" OR Processes.process="*--disable-user-media-security*") by host Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where mvcount(split(cmdline,"--")) >= 3 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "msedge.exe"
| where ProcessCommandLine has "--headless"
| where ProcessCommandLine has_any ("--disable-web-security","--allow-file-access-from-files","--use-fake-ui-for-media-stream","--auto-select-screen-capture-source=true","--disable-user-media-security","--no-sandbox")
| extend FlagCount = countof(ProcessCommandLine, "--disable-web-security") + countof(ProcessCommandLine, "--allow-file-access-from-files") + countof(ProcessCommandLine, "--use-fake-ui-for-media-stream") + countof(ProcessCommandLine, "--auto-select-screen-capture-source") + countof(ProcessCommandLine, "--disable-user-media-security")
| where FlagCount >= 2
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, FlagCount, SHA256
| order by Timestamp desc
```

### DRILLAPP variant 2: Edge launched with --remote-debugging-port=9222 for CDP-based file download

`UC_610_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="msedge.exe" (Processes.process="*--remote-debugging-port=9222*" OR Processes.process="*--remote-debugging-port=*") by host Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | search NOT parent IN ("chromedriver.exe","msedgedriver.exe","node.exe","python.exe","code.exe","devenv.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "msedge.exe"
| where ProcessCommandLine has "--remote-debugging-port"
| extend DebugPort = extract(@"--remote-debugging-port=(\d{2,5})", 1, ProcessCommandLine)
| where isnotempty(DebugPort)
| where InitiatingProcessFileName !in~ ("chromedriver.exe","msedgedriver.exe","node.exe","python.exe","code.exe","devenv.exe","pytest.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ProcessCommandLine, DebugPort, SHA256
| order by Timestamp desc
```

### DRILLAPP variant 1 persistence: LNK file written to user Startup folder by non-Explorer process

`UC_610_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file values(Filesystem.process_name) as parent_proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" Filesystem.file_name="*.lnk" by host Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search NOT parent_proc IN ("explorer.exe","OneDrive.exe","setup.exe","msiexec.exe","TrustedInstaller.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\Microsoft\Windows\Start Menu\Programs\Startup"
| where FileName endswith ".lnk"
| where InitiatingProcessFileName !in~ ("explorer.exe","onedrive.exe","msiexec.exe","setup.exe","trustedinstaller.exe","officeclicktorun.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### DRILLAPP C2 staging: msedge.exe contacting pastefy.app

`UC_610_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dport values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="msedge.exe" (All_Traffic.dest="pastefy.app" OR All_Traffic.dest="*.pastefy.app") by host All_Traffic.app All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "msedge.exe"
| where RemoteUrl has "pastefy.app" or RemoteUrl endswith "pastefy.app"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessId
| order by Timestamp desc
```

### DRILLAPP variant 2 delivery: CPL file executed from user-writable folder spawning Edge

`UC_610_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="rundll32.exe" Processes.process="*shell32.dll,Control_RunDLL*" (Processes.process="*\\AppData\\Local\\Temp\\*" OR Processes.process="*\\AppData\\Roaming\\*" OR Processes.process="*\\Downloads\\*" OR Processes.process="*\\Users\\Public\\*") Processes.process="*.cpl*" by host Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CplLaunch = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "rundll32.exe"
    | where ProcessCommandLine has "shell32.dll,Control_RunDLL"
    | where ProcessCommandLine matches regex @"(?i)\.cpl"
    | where ProcessCommandLine has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Downloads\", @"\Users\Public\")
    | project CplTime=Timestamp, DeviceId, RundllPid=ProcessId, CplCmd=ProcessCommandLine, AccountName, DeviceName;
let EdgeSpawn = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "msedge.exe"
    | project EdgeTime=Timestamp, DeviceId, ParentPid=InitiatingProcessId, EdgeCmd=ProcessCommandLine;
CplLaunch
| join kind=inner EdgeSpawn on DeviceId, $left.RundllPid == $right.ParentPid
| where EdgeTime between (CplTime .. CplTime + 5m)
| project CplTime, EdgeTime, DeviceName, AccountName, CplCmd, EdgeCmd
```

### DRILLAPP C2: msedge.exe egress to known DRILLAPP IPs or WebSocket to localhost:8000

`UC_610_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.dest_port) as dport values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="80.89.224.13" OR All_Traffic.dest="188.137.228.162" OR (All_Traffic.app="msedge.exe" AND All_Traffic.dest IN ("127.0.0.1","::1","localhost") AND All_Traffic.dest_port=8000)) by host All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteIP in ("80.89.224.13","188.137.228.162"))
    or (InitiatingProcessFileName =~ "msedge.exe" and RemoteIP in ("127.0.0.1","::1") and RemotePort == 8000)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
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

### Article-specific behavioural hunt — DRILLAPP: new backdoor targeting Ukrainian entities with possible links to Laund

`UC_610_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — DRILLAPP: new backdoor targeting Ukrainian entities with possible links to Laund ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_path="*%APPDATA%\Microsoft\Windows\Start*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%APPDATA%\Microsoft\Windows\Start*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — DRILLAPP: new backdoor targeting Ukrainian entities with possible links to Laund
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath has_any ("%APPDATA%\Microsoft\Windows\Start"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%APPDATA%\Microsoft\Windows\Start"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `80.89.224.13`, `188.137.228.162`, `pastefy.app`, `short-link.net`, `iili.io`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5b978cdc46afa28d83e532cd19622d9097bebedf87efc4c87bd35d8ffad9e672`, `6178b1af51057c0bac75a842afff500a8fa3ed957d79a712a6ef089bec7e7a8b`, `ac60eefc2607216f8126c0b22b6243f3862ef2bb265c585deee0d00a20a436b3`, `e20831cecd763d0dc91fb39f3bd61d17002608c5a40a6cf0bd16111f4e50d341`, `ee90b01b16099e0bb23d4653607a3a559590fc8d0c43120b8456fb1860d2e630`, `32973ef02e10a585a4a0196b013265e29fc57d8e1c50752f7b39e43b9f388715`, `107b2badfc93fcdd3ffda7d3999477ced3f39f43f458dd0f6a424c9ab52681c3`, `a545908c931ec47884b5ccfb1f112435f5d0cdac140e664673672c9df9016672` _(+18 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
