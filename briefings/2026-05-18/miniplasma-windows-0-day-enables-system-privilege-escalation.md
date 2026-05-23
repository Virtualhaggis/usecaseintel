# [HIGH] MiniPlasma Windows 0-Day Enables SYSTEM Privilege Escalation on Fully Patched Systems

**Source:** The Hacker News
**Published:** 2026-05-18
**Article:** https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html

## Threat Profile

Four Malicious npm Packages Deliver Infostealers and Phantom Bot DDoS Malware 
 Ravie Lakshmanan  May 18, 2026 Supply Chain Attack / Botnet 
Cybersecurity researchers have discovered four new npm packages containing information-stealing malware, one of which is a clone of the Shai-Hulud worm open-sourced by TeamPCP .
The list of identified packages is below -
chalk-tempalte (825 Downloads)
@deadcode09284814/axios-util (284 Downloads)
axois-utils (963 Downloads)
color-style-utils (934 Downloads…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `80.200.28.28`
- **Domain (defanged):** `87e0bbc636999b.lhr.life`
- **Domain (defanged):** `edcf8b03c84634.lhr.life`
- **Domain (defanged):** `b94b6bcfa27554.lhr.life`
- **Domain (defanged):** `f04a273bd84c0622-80-200-28-28.serveousercontent.com`
- **Domain (defanged):** `8a3e818ea8f11186-80-200-28-28.serveousercontent.com`
- **SHA256:** `165fa92d237fd017c227d00da06ab788212a62be94bf61e95df2d22d00377ef2`
- **SHA256:** `7d0ae79fdb1e9968f3323a3712b624643a782ba3efb2cf3a2cb9c4c5513cea30`
- **SHA256:** `308b15c023088a7188dea4ef609010ac2493eb4c365b103053d7621a9ca5b935`
- **SHA256:** `9e380ec88d3ccf3929e1a104e3b868d4d7b59ca189a8a431a54e9f3357dfdd81`
- **SHA256:** `d1c9e3f296ee9f7d5032f73f9c504cede50334bc14c394055fd5cb9c3a6e08b3`
- **SHA256:** `ffba9bdd6793edd5b38e12900252c1813a693f59c25af51c3b658cf3f27b6162`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1053.005** — Scheduled Task
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.002** — Proxy: External Proxy
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1555** — Credentials from Password Stores
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1543.003** — Create or Modify System Process: Windows Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound connection or DNS to Shai-Hulud copycat C2 (lhr.life subdomains / 80.200.28.28:2222)

`UC_121_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.user) as user values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where (All_Traffic.dest="80.200.28.28" AND All_Traffic.dest_port=2222) OR All_Traffic.dest_url IN ("*87e0bbc636999b.lhr.life*","*b94b6bcfa27554.lhr.life*","*edcf8b03c84634.lhr.life*") by All_Traffic.dest All_Traffic.dest_url host | `drop_dm_object_name(All_Traffic)` | append [ | tstats summariesonly=true count from datamodel=Network_Resolution where DNS.query IN ("87e0bbc636999b.lhr.life","b94b6bcfa27554.lhr.life","edcf8b03c84634.lhr.life") by DNS.query DNS.src host | `drop_dm_object_name(DNS)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2Domains = dynamic(["87e0bbc636999b.lhr.life","b94b6bcfa27554.lhr.life","edcf8b03c84634.lhr.life"]);
let C2IP = "80.200.28.28";
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where (RemoteIP == C2IP and RemotePort == 2222)
    or RemoteUrl has_any (C2Domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl,
          Protocol
| order by Timestamp desc
```

### [LLM] Install of typosquatted Shai-Hulud copycat npm packages (chalk-tempalte / axois-utils / color-style-utils / @deadcode09284814/axios-util)

`UC_121_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","node.exe") (Processes.process="*chalk-tempalte*" OR Processes.process="*axois-utils*" OR Processes.process="*color-style-utils*" OR Processes.process="*@deadcode09284814/axios-util*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MalPackages = dynamic(["chalk-tempalte","axois-utils","color-style-utils","@deadcode09284814/axios-util"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","npx.cmd","node.exe")
    or InitiatingProcessFileName in~ ("npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe")
| where ProcessCommandLine has_any (MalPackages)
    or InitiatingProcessCommandLine has_any (MalPackages)
| project Timestamp, DeviceName, AccountName, AccountUpn,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### [LLM] node/npm process reading SSH private keys or cloud credential files (Shai-Hulud infostealer behavior)

`UC_121_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node","npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd") AND (Filesystem.file_path="*\\.ssh\\id_rsa*" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.config\\gcloud*" OR Filesystem.file_path="*/.config/gcloud*" OR Filesystem.file_path="*\\.azure\\accessTokens*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*wallet.dat*" OR Filesystem.file_path="*keystore*") by Filesystem.dest Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)` | where mvcount(file_path) >= 2 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredPaths = dynamic([
  "\\.ssh\\id_rsa","\\.ssh\\id_ed25519","/.ssh/id_rsa","/.ssh/id_ed25519",
  "\\.aws\\credentials","/.aws/credentials",
  "\\.config\\gcloud","/.config/gcloud",
  "\\.azure\\accessTokens","\\.azure\\azureProfile",
  "\\.npmrc","/.npmrc",
  "wallet.dat","keystore","metamask","electrum"
]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd")
| where FolderPath has_any (CredPaths) or FileName has_any (CredPaths)
| where InitiatingProcessParentFileName !in~ ("code.exe","devenv.exe","webstorm64.exe","idea64.exe")
    or ActionType in ("FileCreated","FileModified","FileRenamed")
| summarize PathsTouched = dcount(FolderPath), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Sample = make_set(FolderPath, 10)
        by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where PathsTouched >= 2
| order by LastSeen desc
```

### [LLM] Phantom Bot persistence registration by node/npm context (axois-utils GoLang implant survives package deletion)

`UC_121_12` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as autostart_target values(Registry.process_name) as writing_process from datamodel=Endpoint.Registry where Registry.process_name IN ("node.exe","npm.cmd","npm.exe","yarn.cmd","pnpm.cmd") AND (Registry.registry_path="*\\CurrentVersion\\Run*" OR Registry.registry_path="*\\CurrentVersion\\RunOnce*" OR Registry.registry_path="*\\Services\\*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name | `drop_dm_object_name(Registry)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.cmd","npm.exe") Processes.process_name IN ("schtasks.exe","sc.exe","reg.exe","powershell.exe") (Processes.process="*schtasks*/create*" OR Processes.process="*sc*create*" OR Processes.process="*reg*add*Run*" OR Processes.process="*New-ScheduledTask*" OR Processes.process="*Register-ScheduledTask*") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let NodeProcs = dynamic(["node.exe","npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd"]);
let AutostartKeys = dynamic([
  "\\CurrentVersion\\Run",
  "\\CurrentVersion\\RunOnce",
  "\\CurrentVersion\\Explorer\\Run",
  "\\Services\\",
  "\\Image File Execution Options\\"
]);
(
  DeviceRegistryEvents
  | where Timestamp > ago(14d)
  | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
  | where InitiatingProcessFileName in~ (NodeProcs)
      or InitiatingProcessParentFileName in~ (NodeProcs)
  | where RegistryKey has_any (AutostartKeys)
  | project Timestamp, DeviceName, InitiatingProcessAccountName,
            InitiatingProcessFileName, InitiatingProcessParentFileName,
            InitiatingProcessCommandLine, RegistryKey, RegistryValueName,
            RegistryValueData, Source="Registry"
)
| union
(
  DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where InitiatingProcessFileName in~ (NodeProcs)
  | where FileName in~ ("schtasks.exe","sc.exe","reg.exe","powershell.exe","pwsh.exe")
  | where ProcessCommandLine has_any ("/create","create binPath","reg add","\\Run","Register-ScheduledTask","New-ScheduledTask")
  | project Timestamp, DeviceName, InitiatingProcessAccountName=AccountName,
            InitiatingProcessFileName, InitiatingProcessParentFileName,
            InitiatingProcessCommandLine=ProcessCommandLine,
            RegistryKey="", RegistryValueName="", RegistryValueData=FileName, Source="ProcessSpawn"
)
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
  - IP / domain IOC(s): `80.200.28.28`, `87e0bbc636999b.lhr.life`, `edcf8b03c84634.lhr.life`, `b94b6bcfa27554.lhr.life`, `f04a273bd84c0622-80-200-28-28.serveousercontent.com`, `8a3e818ea8f11186-80-200-28-28.serveousercontent.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `165fa92d237fd017c227d00da06ab788212a62be94bf61e95df2d22d00377ef2`, `7d0ae79fdb1e9968f3323a3712b624643a782ba3efb2cf3a2cb9c4c5513cea30`, `308b15c023088a7188dea4ef609010ac2493eb4c365b103053d7621a9ca5b935`, `9e380ec88d3ccf3929e1a104e3b868d4d7b59ca189a8a431a54e9f3357dfdd81`, `d1c9e3f296ee9f7d5032f73f9c504cede50334bc14c394055fd5cb9c3a6e08b3`, `ffba9bdd6793edd5b38e12900252c1813a693f59c25af51c3b658cf3f27b6162`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
