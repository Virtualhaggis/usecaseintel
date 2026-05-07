# [CRIT] MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware Attack

**Source:** The Hacker News
**Published:** 2026-05-06
**Article:** https://thehackernews.com/2026/05/muddywater-uses-microsoft-teams-to.html

## Threat Profile

MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware Attack 
 Ravie Lakshmanan  May 06, 2026 Ransomware / Cybercrime 
The Iranian state-sponsored hacking group known as MuddyWater (aka Mango Sandstorm, Seedworm, and Static Kitten) has been attributed to a ransomware attack in what has been described as a "false flag" operation.
The attack, observed by Rapid7 in early 2026, has been found to leverage social engineering techniques via Microsoft Teams to initiate the infe…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`
- **IPv4 (defanged):** `172.86.126.208`
- **IPv4 (defanged):** `172.86.76.127`
- **Domain (defanged):** `mjla.gov.om`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1574.002** — DLL Side-Loading
- **T1036.005** — Match Legitimate Name or Location
- **T1078** — Valid Accounts
- **T1059.003** — Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Stagecomp/Darkcomp staging artifacts (ms_upd.exe, game.exe, visualwincomp.txt) on disk

`UC_25_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_name IN ("ms_upd.exe","game.exe","visualwincomp.txt") OR (Filesystem.file_name="WebView2Loader.dll" AND NOT Filesystem.file_path IN ("*\\Microsoft\\Edge\\*","*\\Microsoft\\EdgeWebView\\*","*\\Program Files*\\WindowsApps\\*"))) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | eventstats dc(file_name) as DistinctArtifacts by dest, file_path | where DistinctArtifacts>=2 OR file_name="visualwincomp.txt" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Stagecomp/Darkcomp dropper artifacts written together
let StagecompFiles = dynamic(["ms_upd.exe","game.exe","visualwincomp.txt"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where (FileName in~ (StagecompFiles))
   or (FileName =~ "WebView2Loader.dll"
        and not(FolderPath has_any (@"\Microsoft\Edge\", @"\Microsoft\EdgeWebView\", @"\WindowsApps\")))
| summarize FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            DistinctArtifacts = dcount(FileName),
            Files = make_set(FileName, 16),
            Hashes = make_set(SHA256, 16),
            DropperPaths = make_set(FolderPath, 8),
            DroppedBy = make_set(InitiatingProcessFileName, 8),
            DropperCmd = any(InitiatingProcessCommandLine)
            by DeviceName, FolderPath
| where DistinctArtifacts >= 2 or Files has "visualwincomp.txt"
| order by FirstSeen desc
```

### [LLM] Microsoft Teams spawning DWAgent / AnyDesk / Quick Assist installer (MuddyWater Chaos vishing chain)

`UC_25_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("ms-teams.exe","Teams.exe","msteams.exe") OR Processes.parent_process="*\\Microsoft\\Teams\\*" OR Processes.parent_process="*\\WindowsApps\\MSTeams_*") AND (Processes.process_name IN ("dwagent.exe","dwagsvc.exe","dwagent-x64.exe","AnyDesk.exe","AnyDeskMSI.exe","quickassist.exe") OR Processes.process IN ("*dwagent*","*anydesk*","*quickassist*") OR Processes.process="*-CmdId QuickAssist*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Teams desktop spawning a remote-management tool — MuddyWater Chaos vishing chain
let TeamsParents = dynamic(["ms-teams.exe","Teams.exe","msteams.exe"]);
let RmmChildren  = dynamic(["dwagent.exe","dwagsvc.exe","dwagent-x64.exe","AnyDesk.exe","AnyDeskMSI.exe","quickassist.exe","QuickAssist.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ (TeamsParents)
     or InitiatingProcessFolderPath has @"\Microsoft\Teams\"
     or InitiatingProcessFolderPath matches regex @"(?i)\\WindowsApps\\MSTeams_"
| where FileName in~ (RmmChildren)
     or ProcessCommandLine has_any ("dwagent","anydesk","quickassist")
     or ProcessCommandLine has "-CmdId QuickAssist"
| project Timestamp, DeviceName, AccountName, AccountUpn,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          IsRemote    = InitiatingProcessAccountName,
          SHA256
| order by Timestamp desc
```

### [LLM] Curl/LOLBin retrieval of Stagecomp loader from MuddyWater C2 172.86.126.208

`UC_25_13` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl.exe","powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe","wget.exe")) AND (Processes.process="*172.86.126.208*" OR Processes.process="*ms_upd.exe*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="172.86.126.208" by All_Traffic.src All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Stagecomp delivery from 172.86.126.208 — process side
let C2Ip = "172.86.126.208";
let Loaders = dynamic(["curl.exe","powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe","wget.exe","mshta.exe"]);
let ProcHits =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (Loaders)
    | where ProcessCommandLine has C2Ip
         or ProcessCommandLine has "ms_upd.exe"
    | project Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              IsRemoteSession = InitiatingProcessAccountName,
              Source = "Process";
let NetHits =
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP == C2Ip
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              FileName = InitiatingProcessFileName,
              ProcessCommandLine = InitiatingProcessCommandLine,
              InitiatingProcessFileName = InitiatingProcessParentFileName,
              InitiatingProcessCommandLine = "",
              IsRemoteSession = "",
              Source = "Network";
ProcHits
| union NetHits
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware At

`UC_25_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware At ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("ms_upd.exe","game.exe","webview2loader.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("ms_upd.exe","game.exe","webview2loader.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — MuddyWater Uses Microsoft Teams to Steal Credentials in False Flag Ransomware At
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("ms_upd.exe", "game.exe", "webview2loader.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("ms_upd.exe", "game.exe", "webview2loader.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `172.86.126.208`, `172.86.76.127`, `mjla.gov.om`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
