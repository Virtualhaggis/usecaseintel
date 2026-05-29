# [CRIT] axios Compromised on npm - Malicious Versions Drop Remote Access Trojan

**Source:** StepSecurity
**Published:** 2026-04-09
**Article:** https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan

## Threat Profile

Back to Blog Threat Intel axios Compromised on npm - Malicious Versions Drop Remote Access Trojan Hijacked maintainer account used to publish poisoned axios releases including 1.14.1 and 0.30.4. The attacker injected a hidden dependency that drops a cross platform RAT. We are actively investigating and will update this post with a full technical analysis. Ashish Kurmi View LinkedIn March 30, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loa…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sfrclak.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1105** — Ingress Tool Transfer
- **T1070.004** — Indicator Removal: File Deletion
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] axios Supply Chain RAT C2 Callback to sfrclak.com (Port 8000)

`UC_178_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Resolution.DNS.src) as src values(Network_Resolution.DNS.answer) as answer from datamodel=Network_Resolution where Network_Resolution.DNS.query="*sfrclak.com" by Network_Resolution.DNS.query | `drop_dm_object_name("DNS")` | append [ | tstats summariesonly=t count from datamodel=Network_Traffic where (Network_Traffic.All_Traffic.dest="sfrclak.com" OR Network_Traffic.All_Traffic.dest_host="sfrclak.com") AND Network_Traffic.All_Traffic.dest_port=8000 by Network_Traffic.All_Traffic.src, Network_Traffic.All_Traffic.dest, Network_Traffic.All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")` ] | sort - firstTime
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents
   | where Timestamp > ago(7d)
   | where RemoteUrl has "sfrclak.com" or (tolower(RemoteUrl) endswith "sfrclak.com" and RemotePort == 8000)
   | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, RemotePort, Evidence="network_connect"),
  (DeviceEvents
   | where Timestamp > ago(7d)
   | where ActionType in ("DnsQueryResponse","DnsConnectionInspected")
   | where AdditionalFields has "sfrclak.com" or RemoteUrl has "sfrclak.com"
   | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, Evidence="dns_query")
| order by Timestamp desc
```

### [LLM] npm postinstall node setup.js dropper executing from plain-crypto-js with immediate network egress

`UC_178_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process_cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","npm") AND Processes.process_name IN ("node.exe","node") AND (Processes.process="*plain-crypto-js*setup.js*" OR Processes.process="*\\plain-crypto-js\\setup.js*" OR Processes.process="*/plain-crypto-js/setup.js*") by host, user, Processes.process_id, Processes.process, Processes.parent_process | `drop_dm_object_name("Processes")` | rename process_id as proc_id | join type=left host proc_id [| tstats summariesonly=t count from datamodel=Network_Traffic where All_Traffic.app="node.exe" OR All_Traffic.process_name="node.exe" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.process_id | `drop_dm_object_name("All_Traffic")` | rename src as host, process_id as proc_id ] | where isnotnull(dest)
```

**Defender KQL:**
```kql
let SetupRun = DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where FileName in~ ("node.exe","node")
  | where InitiatingProcessFileName in~ ("npm.exe","node.exe","npm","npm-cli.js","yarn.exe","pnpm.exe","pnpm","yarn")
     or InitiatingProcessCommandLine has_any ("npm install","npm i ","npm ci","yarn install","pnpm install")
  | where ProcessCommandLine has "setup.js"
  | where ProcessCommandLine has "plain-crypto-js" or InitiatingProcessFolderPath has "plain-crypto-js" or FolderPath has "plain-crypto-js"
  | project SetupTime=Timestamp, DeviceId, DeviceName, AccountName, ProcessId, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName;
SetupRun
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("node.exe","node")
    | where RemoteIPType == "Public"
    | project NetTime=Timestamp, DeviceId, ChildProcId=InitiatingProcessId, RemoteIP, RemoteUrl, RemotePort
  ) on DeviceId
| where ChildProcId == ProcessId
| where datetime_diff('second', NetTime, SetupTime) between (0 .. 60)
| project SetupTime, NetTime, DelaySec=datetime_diff('second', NetTime, SetupTime), DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by SetupTime desc
```

### [LLM] Malicious axios or plain-crypto-js package files written to node_modules

`UC_178_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\plain-crypto-js\\setup.js*" OR Filesystem.file_path="*/node_modules/plain-crypto-js/setup.js*" OR Filesystem.file_path="*\\node_modules\\plain-crypto-js\\package.md*" OR Filesystem.file_path="*/node_modules/plain-crypto-js/package.md*") by host, Filesystem.file_path, Filesystem.file_name | `drop_dm_object_name("Filesystem")` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\node_modules\plain-crypto-js" or FolderPath has "/node_modules/plain-crypto-js")
   and FileName in~ ("setup.js","package.md","package.json")
| extend IsDropper = (FileName =~ "setup.js")
| extend IsAntiForensic = (FileName =~ "package.md")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256, FileSize, IsDropper, IsAntiForensic
| order by Timestamp desc
```

### [LLM] plain-crypto-js setup.js self-deletion or package.json overwrite (anti-forensics)

`UC_178_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as writer values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where ((Filesystem.action="deleted" AND (Filesystem.file_path="*\\node_modules\\plain-crypto-js\\setup.js*" OR Filesystem.file_path="*/node_modules/plain-crypto-js/setup.js*")) OR (Filesystem.action IN ("modified","created") AND (Filesystem.file_path="*\\node_modules\\plain-crypto-js\\package.json*" OR Filesystem.file_path="*/node_modules/plain-crypto-js/package.json*") AND Filesystem.process_name="node.exe")) by host, Filesystem.file_path, Filesystem.action | `drop_dm_object_name("Filesystem")` | sort - firstTime
```

**Defender KQL:**
```kql
let TargetDir = "plain-crypto-js";
let Deletions = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("FileDeleted","FileRenamed")
  | where FolderPath has TargetDir
  | where FileName =~ "setup.js" or PreviousFileName =~ "setup.js"
  | project DelTime=Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, DelActor=InitiatingProcessFileName, DelActorCmd=InitiatingProcessCommandLine, DelPath=FolderPath;
let Rewrites = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("FileModified","FileCreated")
  | where FolderPath has TargetDir and FileName =~ "package.json"
  | where InitiatingProcessFileName in~ ("node.exe","node")
  | project RewriteTime=Timestamp, DeviceId, RewriteActor=InitiatingProcessFileName, RewriteCmd=InitiatingProcessCommandLine, RewriteSHA=SHA256;
Deletions
| join kind=inner Rewrites on DeviceId
| where abs(datetime_diff('second', RewriteTime, DelTime)) <= 30
| project DelTime, RewriteTime, DeviceName, AccountName, DelActor, DelActorCmd, DelPath, RewriteActor, RewriteCmd, RewriteSHA
| order by DelTime desc
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

### Article-specific behavioural hunt — axios Compromised on npm - Malicious Versions Drop Remote Access Trojan

`UC_178_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — axios Compromised on npm - Malicious Versions Drop Remote Access Trojan ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.js","index.js","aes.js","cipher-core.js","core.js","node.js","wt.exe","6202033.ps1","6202033.vbs","stepsecurity-dev-machine-guard.sh","dev-machine-guard.sh") OR Processes.process="*-WindowStyle Hidden*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/ld.py*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/tmp/6202033*" OR Filesystem.file_path="*/Library/Caches/com.apple.act.mond*" OR Filesystem.file_path="*/home/runner/work/_temp*" OR Filesystem.file_path="*/etc/hosts*" OR Filesystem.file_name IN ("setup.js","index.js","aes.js","cipher-core.js","core.js","node.js","wt.exe","6202033.ps1","6202033.vbs","stepsecurity-dev-machine-guard.sh","dev-machine-guard.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — axios Compromised on npm - Malicious Versions Drop Remote Access Trojan
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.js", "index.js", "aes.js", "cipher-core.js", "core.js", "node.js", "wt.exe", "6202033.ps1", "6202033.vbs", "stepsecurity-dev-machine-guard.sh", "dev-machine-guard.sh") or ProcessCommandLine has_any ("-WindowStyle Hidden"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/ld.py", "/dev/null", "/tmp/6202033", "/Library/Caches/com.apple.act.mond", "/home/runner/work/_temp", "/etc/hosts") or FileName in~ ("setup.js", "index.js", "aes.js", "cipher-core.js", "core.js", "node.js", "wt.exe", "6202033.ps1", "6202033.vbs", "stepsecurity-dev-machine-guard.sh", "dev-machine-guard.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sfrclak.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
