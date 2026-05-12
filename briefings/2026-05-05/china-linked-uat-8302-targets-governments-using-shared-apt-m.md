# [CRIT] China-Linked UAT-8302 Targets Governments Using Shared APT Malware Across Regions

**Source:** The Hacker News
**Published:** 2026-05-05
**Article:** https://thehackernews.com/2026/05/china-linked-uat-8302-targets.html

## Threat Profile

China-Linked UAT-8302 Targets Governments Using Shared APT Malware Across Regions 
 Ravie Lakshmanan  May 05, 2026 Network Security / Endpoint Security 
A sophisticated China-nexus advanced persistent threat (APT) group has been attributed to attacks targeting government entities in South America since at least late 2024 and government agencies in southeastern Europe in 2025.
The activity is being tracked by Cisco Talos under the moniker UAT-8302 , with post-exploitation involving the deployme…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567** — Exfiltration Over Web Service
- **T1046** — Network Service Discovery
- **T1018** — Remote System Discovery
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1572** — Protocol Tunneling
- **T1090.001** — Proxy: Internal Proxy
- **T1090.002** — Proxy: External Proxy
- **T1133** — External Remote Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] NetDraft/FINALDRAFT covert C2 — non-mail process beaconing to Microsoft Graph (Outlook drafts channel)

`UC_80_4` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as destinations values(All_Traffic.process_name) as process_name values(All_Traffic.process) as process from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("graph.microsoft.com","login.microsoftonline.com") AND NOT All_Traffic.process_name IN ("outlook.exe","OUTLOOK.EXE","teams.exe","ms-teams.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe","onedrive.exe","winword.exe","excel.exe","powerpnt.exe","onenote.exe","officeclicktorun.exe","olk.exe","explorer.exe","sharepoint.exe","msaccess.exe","powerautomatedesktop.exe","code.exe","pwsh.exe") by All_Traffic.src, All_Traffic.user, All_Traffic.process_name, All_Traffic.process_hash, All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort 0 - count
```

**Defender KQL:**
```kql
let _mail_browser_allow = dynamic(["outlook.exe","olk.exe","teams.exe","msteams.exe","ms-teams.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe","onedrive.exe","winword.exe","excel.exe","powerpnt.exe","onenote.exe","officeclicktorun.exe","sharepoint.exe","explorer.exe","msaccess.exe","code.exe","powerautomatedesktop.exe","searchapp.exe","searchhost.exe","settingshost.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("graph.microsoft.com","login.microsoftonline.com") or RemoteUrl endswith ".graph.microsoft.com"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ (_mail_browser_allow)
| summarize ConnCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctMinutes=dcount(bin(Timestamp,1m)), DestUrls=make_set(RemoteUrl,8)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where ConnCount >= 3                  // suppress one-shot legit OAuth probes
| order by ConnCount desc
```

### [LLM] UAT-8302 internal recon — chainreactors `gogo` scanner cmdline tokens

`UC_80_5` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.user!="*$" AND ( Processes.process_name IN ("gogo.exe","gogo_windows_amd64.exe","gogo_windows_386.exe") OR Processes.process="*gogo.exe *" OR Processes.process="*gogo_windows_amd64.exe*" OR Processes.process="* --mod s *" OR Processes.process="* --mod ss *" OR Processes.process="* -p top1*" OR Processes.process="* -p top2*" OR Processes.process="* -p top3*" OR Processes.process="* -p win *" OR Processes.process="* -p db *" OR Processes.process="* -p all*" OR Processes.process="* --af *") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName matches regex @"(?i)^gogo(_windows_(amd64|386))?\.exe$")
     or (ProcessCommandLine matches regex @"(?i)\\gogo(_windows_(amd64|386))?\.exe\b")
     or (ProcessCommandLine has_any ("--mod s ","--mod ss "))
     or (ProcessCommandLine matches regex @"(?i)\s-p\s+(top1|top2|top3|win|db|all|rce|ws)\b")
     or (ProcessCommandLine has " --af " and ProcessCommandLine has " -i ")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          IsInitiatingProcessRemoteSession
| order by Timestamp desc
```

### [LLM] UAT-8302 alternate access — Stowaway pivot agent or SoftEther VPN client install

`UC_80_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.user!="*$" AND ( Processes.process_name IN ("stowaway_agent.exe","stowaway_admin.exe","vpncmd.exe","vpncmd_x64.exe","vpnclient.exe","vpnclient_x64.exe","vpnserver.exe","vpnserver_x64.exe","vpnbridge.exe","vpnbridge_x64.exe","vpninstall.exe") OR Processes.process="*--cs gbk*" OR Processes.process="*vpncmd*AccountConnect*" OR Processes.process="*vpncmd*NicCreate*" OR Processes.process="*vpncmd*HubCreate*" OR Processes.process="*vpncmd*/server*:443*/client*" OR Processes.process="*stowaway_agent*-l 0.0.0.0:*" OR Processes.process="*stowaway_agent*-c *:*-s *") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName matches regex @"(?i)^(stowaway_(agent|admin)|vpncmd(_x64)?|vpnclient(_x64)?|vpnserver(_x64)?|vpnbridge(_x64)?|vpninstall)\.exe$")
     or (ProcessCommandLine has "--cs gbk")
     or (ProcessCommandLine matches regex @"(?i)\bvpncmd(_x64)?(\.exe)?\b.*\b(AccountConnect|NicCreate|HubCreate|AccountCreate|NicEnable)\b")
     or (ProcessCommandLine matches regex @"(?i)\bstowaway_(agent|admin)(\.exe)?\b.*\s-(l|c)\s+\S+.*\s-s\s+\S+")
     or (ProcessCommandLine matches regex @"(?i)\bvpncmd(_x64)?\.exe\b.*\/server\s+\S+:(443|992|5555|1194)")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          IsInitiatingProcessRemoteSession
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
