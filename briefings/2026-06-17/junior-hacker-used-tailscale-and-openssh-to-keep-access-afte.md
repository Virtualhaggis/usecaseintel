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
- **T1021.004** — Remote Services: SSH
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1204.002** — User Execution: Malicious File
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1653** — Power Settings
- **T1568** — Dynamic Resolution
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Tailscale mesh-VPN client install/exec on Windows endpoint (Operation Poisson parallel persistence)

`UC_111_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("tailscale.exe","tailscaled.exe") OR Processes.process="*tailscale up*" OR Processes.process="*login.tailscale.com*" OR Processes.process="*--authkey*") AND NOT Processes.user IN ("*$","SYSTEM","LOCAL SERVICE","NETWORK SERVICE") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("tailscale.exe","tailscaled.exe")
   or ProcessCommandLine has_any ("tailscale up","login.tailscale.com","--authkey","tailscale.exe up")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Tailscale WireGuard egress (UDP 41641 / CGNAT 100.64.0.0/10 / *.ts.net) out-of-band C2 channel

`UC_111_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port=41641 AND All_Traffic.transport="udp") OR All_Traffic.dest="100.64.0.0/10" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemotePort == 41641 and Protocol =~ "Udp")
   or RemoteUrl has_any ("login.tailscale.com","controlplane.tailscale.com",".ts.net")
   or ipv4_is_in_any_range(RemoteIP, "100.64.0.0/10")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### OpenSSH Server feature install / sshd service creation on Windows workstation

`UC_111_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process IN ("*OpenSSH.Server*","*Add-WindowsCapability*OpenSSH*","*Set-Service*sshd*","*Start-Service sshd*","*sc*create*sshd*") OR Processes.process_name="sshd.exe") AND NOT Processes.user IN ("*$") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has_any ("OpenSSH.Server","Add-WindowsCapability","Start-Service sshd","Set-Service sshd","sc create sshd","sc.exe create sshd")
   or FileName =~ "sshd.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SSH authorized_keys provisioning / ssh-keygen on Windows endpoint (key-based backdoor)

`UC_111_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("authorized_keys","administrators_authorized_keys") OR Filesystem.file_path="*\\.ssh\\*" OR Filesystem.file_path="*\\ProgramData\\ssh\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("authorized_keys","administrators_authorized_keys")
   or (FolderPath has ".ssh" and FileName !endswith ".tmp")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### OpenSSH reverse tunnel (ssh -R) to external host — out-of-band C2 fallback

`UC_111_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="ssh.exe" AND Processes.process="*-R *" AND NOT Processes.user IN ("*$") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName =~ "ssh.exe"
| where ProcessCommandLine matches regex @"(?i)\s-R\s+\S"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### wscript.exe executing .vbs from user staging folder (Poisson VBScript stager)

`UC_111_15` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") AND Processes.process="*.vbs*" AND (Processes.process IN ("*\\AppData\\*","*\\Temp\\*","*\\Public\\*","*\\Downloads\\*")) AND NOT Processes.user IN ("*$") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has ".vbs"
| where ProcessCommandLine has_any ("AppData","\\Temp\\","\\Public\\","Downloads","%TEMP%","%APPDATA%")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Scheduled task at logon with highest privileges launching a script interpreter

`UC_111_16` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="schtasks.exe" AND Processes.process="*create*" AND Processes.process="*highest*" AND Processes.process="*onlogon*") OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND Processes.process="*Register-ScheduledTask*" AND Processes.process="*Highest*")) AND (Processes.process IN ("*wscript*","*cscript*","*powershell*","*mshta*","*.vbs*","*.ps1*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where (FileName =~ "schtasks.exe" and ProcessCommandLine has "create" and ProcessCommandLine has "highest" and ProcessCommandLine has "onlogon")
     or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Register-ScheduledTask" and ProcessCommandLine has "Highest")
| where ProcessCommandLine has_any ("wscript","cscript","powershell","mshta",".vbs",".ps1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### powercfg standby/monitor-timeout set to never (keep host awake for keylogger harvesting)

`UC_111_17` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powercfg.exe" AND (Processes.process="*standby-timeout-ac 0*" OR Processes.process="*standby-timeout-dc 0*" OR Processes.process="*monitor-timeout-ac 0*" OR Processes.process="*monitor-timeout-dc 0*" OR Processes.process="*hibernate-timeout-ac 0*") AND NOT Processes.user IN ("*$") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName =~ "powercfg.exe"
| where ProcessCommandLine matches regex @"(?i)(standby|monitor|hibernate)-timeout-(ac|dc)\s+0\b"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### DuckDNS dynamic-DNS resolution from endpoint (Havoc/Poisson C2 infrastructure)

`UC_111_18` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*duckdns.org" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "duckdns.org"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
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

`UC_111_9` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 19 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
