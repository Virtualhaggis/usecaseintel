# [CRIT] Junior Hacker Used Tailscale and OpenSSH to Keep Access After His C2 Went Offline

**Source:** The Hacker News
**Published:** 2026-06-17
**Article:** https://thehackernews.com/2026/06/junior-hacker-used-tailscale-and.html

## Threat Profile

Junior Hacker Used Tailscale and OpenSSH to Keep Access After His C2 Went Offline 
 Swati Khandelwal  Jun 17, 2026 Malware / Cyber Attack 
A French-speaking attacker broke into a small French automotive business, planted a keylogger, and stole banking and email credentials.
Ordinary stuff, until one move near the end.
Before his command-and-control server went dark, he installed OpenSSH and Tailscale on a victim's machine, building a way back in that did not run through the C2 at all. When the…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `100.100.100.2`
- **Domain (defanged):** `duckdns.org`
- **Domain (defanged):** `login.tailscale.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1572** — Protocol Tunneling
- **T1090** — Proxy
- **T1133** — External Remote Services
- **T1543.003** — Windows Service
- **T1021.004** — Remote Services: SSH
- **T1090.001** — Internal Proxy
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1562** — Impair Defenses
- **T1071.004** — Application Layer Protocol: DNS
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1547** — Boot or Logon Autostart Execution
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1204.002** — User Execution: Malicious File
- **T1497.003** — Virtualization/Sandbox Evasion: Time-Based Evasion

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Tailscale install or first connect on Windows workstation (Poisson covert C2 mesh)

`UC_8_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("tailscale.exe","tailscaled.exe","tailscale-ipn.exe") OR Processes.process IN ("*tailscale up*","*tailscale login*","*--auth-key*","*--authkey*","*TailscaleSetup*") OR Processes.process_path="*\\Tailscale\\*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$") | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let TailscaleProcs = dynamic(["tailscale.exe","tailscaled.exe","tailscale-ipn.exe"]);
let ProcSig = DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ (TailscaleProcs)
    or InitiatingProcessFileName in~ (TailscaleProcs)
    or ProcessCommandLine has_any ("tailscale up","tailscale login","--auth-key","--authkey","TailscaleSetup")
    or FolderPath has @"\Tailscale\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, Signal="process";
let NetSig = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("login.tailscale.com","controlplane.tailscale.com","derp") and RemoteUrl endswith "tailscale.com"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName=InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256=InitiatingProcessSHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, Signal=strcat("net:",RemoteUrl);
union ProcSig, NetSig
| order by Timestamp desc
```

### OpenSSH Server feature install or sshd service creation on Windows workstation

`UC_8_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process IN ("*Add-WindowsCapability*OpenSSH.Server*","*DISM*/Online*/Add-Capability*OpenSSH.Server*","*Install-WindowsFeature*OpenSSH-Server*","*Set-Service*sshd*","*New-Service*sshd*","*sc*config*sshd*","*sc.exe*create*sshd*") OR Processes.process_name="sshd.exe") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (ProcessCommandLine has "Add-WindowsCapability" and ProcessCommandLine has "OpenSSH.Server")
    or (ProcessCommandLine has "DISM" and ProcessCommandLine has "OpenSSH.Server" and ProcessCommandLine has "Add-Capability")
    or (ProcessCommandLine has "Install-WindowsFeature" and ProcessCommandLine has "OpenSSH-Server")
    or (FileName =~ "sc.exe" and ProcessCommandLine has "sshd" and ProcessCommandLine has_any ("create","config","start"))
    or FileName =~ "sshd.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| join kind=leftouter (
    DeviceInfo | summarize arg_max(Timestamp, DeviceType, DeviceCategory) by DeviceId
  ) on DeviceId
| where DeviceType !in ("Server","DomainController")
| order by Timestamp desc
```

### Outbound ssh.exe with -R reverse-tunnel flag from Windows endpoint

`UC_8_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="ssh.exe" AND (Processes.process="* -R *" OR Processes.process="*-R[0-9]*" OR Processes.process="*--remote-forward*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$") | rex field=process "(?<tunnel_spec>-R\s*\S+)" | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "ssh.exe"
| where ProcessCommandLine matches regex @"(?i)(^|\s)-R\s*\d+:|(^|\s)-R\s*\[?[0-9a-f:.]+\]?:\d+:"
    or ProcessCommandLine has "--remote-forward"
| extend TunnelSpec = extract(@"(?i)-R\s*([^\s]+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, TunnelSpec, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### powercfg standby-timeout zeroed to defeat sleep (keylogger continuous harvest)

`UC_8_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powercfg.exe" AND (Processes.process="*standby-timeout*" OR Processes.process="*monitor-timeout*" OR Processes.process="*hibernate-timeout*" OR Processes.process="*-change*" OR Processes.process="*-setacvalueindex*" OR Processes.process="*-setdcvalueindex*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$") | rex field=process "(?<timeout_value>(standby|monitor|hibernate)-timeout-(ac|dc)\s+\d+)" | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where FileName =~ "powercfg.exe"
| where ProcessCommandLine has_any ("standby-timeout-ac","standby-timeout-dc","monitor-timeout-ac","monitor-timeout-dc","hibernate-timeout-ac","hibernate-timeout-dc")
    or ProcessCommandLine matches regex @"(?i)(standby|monitor|hibernate)-timeout-(ac|dc)\s+0\b"
    or (ProcessCommandLine has "-change" and ProcessCommandLine has_any ("standby","monitor","hibernate"))
| extend ZeroTimeout = ProcessCommandLine matches regex @"(?i)(standby|monitor|hibernate)-timeout-(ac|dc)\s+0\b"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ZeroTimeout, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### DuckDNS resolution from non-browser process (Poisson C2 channel)

`UC_8_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*.duckdns.org" by DNS.src, DNS.query, DNS.dest, DNS.src_user_id | `drop_dm_object_name(DNS)` | join type=left src [ | tstats `summariesonly` count as proc_count, values(Processes.process_name) as process_names from datamodel=Endpoint.Processes where Processes.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","safari.exe") by Processes.dest | rename Processes.dest as src | fields src process_names ] | where isnull(process_names) OR mvcount(process_names)=0 | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let BrowserBins = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","safari.exe","arc.exe","vivaldi.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where (RemoteUrl endswith ".duckdns.org" or RemoteUrl == "duckdns.org")
| where InitiatingProcessFileName !in~ (BrowserBins)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### Logon-triggered scheduled task with HIGHEST runlevel invoking script interpreter

`UC_8_15` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="schtasks.exe" AND Processes.process="*/create*" AND Processes.process="*/rl*HIGHEST*" AND (Processes.process="*/sc*ONLOGON*" OR Processes.process="*/sc*onlogon*") AND (Processes.process="*wscript*" OR Processes.process="*cscript*" OR Processes.process="*powershell*" OR Processes.process="*mshta*" OR Processes.process="*pwsh*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND Processes.process="*Register-ScheduledTask*" AND Processes.process="*Highest*" AND Processes.process="*AtLogOn*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$") | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let ScriptInterps = dynamic(["wscript","cscript","powershell","pwsh","mshta","rundll32","regsvr32","cmd"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (FileName =~ "schtasks.exe"
         and ProcessCommandLine has "/create"
         and ProcessCommandLine matches regex @"(?i)/rl\s+highest"
         and ProcessCommandLine matches regex @"(?i)/sc\s+onlogon"
         and ProcessCommandLine has_any (ScriptInterps))
    or (FileName in~ ("powershell.exe","pwsh.exe")
        and ProcessCommandLine has "Register-ScheduledTask"
        and ProcessCommandLine has "Highest"
        and ProcessCommandLine has_any ("AtLogOn","AtLogon"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### wscript.exe executing .vbs from user staging folder (Havoc VBScript stager)

`UC_8_16` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") AND (Processes.process="*.vbs*" OR Processes.process="*.vbe*" OR Processes.process="*.wsf*") AND (Processes.process="*\\Temp\\*" OR Processes.process="*\\AppData\\*" OR Processes.process="*\\Downloads\\*" OR Processes.process="*\\Public\\*" OR Processes.process="*\\ProgramData\\*" OR Processes.process="*\\Users\\Public\\*") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$") | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let StagingPaths = dynamic([@"\Temp\",@"\AppData\Local\Temp\",@"\AppData\Roaming\",@"\Downloads\",@"\Users\Public\",@"\ProgramData\"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".vbs",".vbe",".wsf")
| where ProcessCommandLine has_any (StagingPaths)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Junior Hacker Used Tailscale and OpenSSH to Keep Access After His C2 Went Offlin

`UC_8_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Junior Hacker Used Tailscale and OpenSSH to Keep Access After His C2 Went Offlin ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("tailscale.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("tailscale.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Junior Hacker Used Tailscale and OpenSSH to Keep Access After His C2 Went Offlin
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("tailscale.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("tailscale.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `100.100.100.2`, `duckdns.org`, `login.tailscale.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 30 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
