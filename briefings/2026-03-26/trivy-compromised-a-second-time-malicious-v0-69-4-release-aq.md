# [HIGH] Trivy Compromised a Second Time - Malicious v0.69.4 Release, aquasecurity/setup-trivy, aquasecurity/trivy-action GitHub Actions Compromised

**Source:** StepSecurity
**Published:** 2026-03-26
**Article:** https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release

## Threat Profile

Back to Blog Threat Intel Trivy Compromised a Second Time - Malicious v0.69.4 Release, aquasecurity/setup-trivy, aquasecurity/trivy-action GitHub Actions Compromised On March 19, 2026, aquasecurity/trivy-action — a widely used GitHub Action for running the Trivy vulnerability scanner — was compromised for approximately 12 hours. A credential stealer was injected into the action via imposter commits, affecting all tags from 0.0.1 through 0.34.2. The compromised action read GitHub Actions Runner w…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `scan.aquasecurtiy.org`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1583.001** — Acquire Infrastructure: Domains
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1003** — OS Credential Dumping
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1140** — Deobfuscate/Decode Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Trivy supply-chain C2 beacon to typosquat domain scan.aquasecurtiy.org

`UC_325_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query="*aquasecurtiy.org" OR DNS.query="scan.aquasecurtiy.org" by DNS.src DNS.query DNS.answer DNS.dest 
| `drop_dm_object_name(DNS)` 
| append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*aquasecurtiy.org*" OR Web.dest="*aquasecurtiy.org*" by Web.src Web.user Web.url Web.dest Web.http_user_agent 
| `drop_dm_object_name(Web)` ] 
| append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest="*aquasecurtiy*" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app 
| `drop_dm_object_name(All_Traffic)` ] 
| sort - firstTime
```

**Defender KQL:**
```kql
let bad_domain = "aquasecurtiy.org";
union isfuzzy=true
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has bad_domain or AdditionalFields has bad_domain
  | project Timestamp, DeviceName, DeviceId, ActionType, RemoteUrl, RemoteIP, RemotePort,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessFolderPath, InitiatingProcessAccountName ),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
  | where QueryName has bad_domain
  | project Timestamp, DeviceName, DeviceId, ActionType, QueryName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessFolderPath, InitiatingProcessAccountName )
| order by Timestamp desc
```

### [LLM] Compromised trivy binary (v0.69.4-v0.69.6) execution by SHA1 hash

`UC_325_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_sha1 IN ("f77738448eec70113cf711656914b61905b3bd47","b9faa60f85f6f780a34b8d0faaf45b3e3966fdda","3c615ac0f29e743eda8863377f9776619fd2db76","c19401b2f58dc6d2632cb473d44be98dd8292a93","4209dcadeaea6a7df69262fef1beeda940881d4d","61fbe20b7589e6b61eedcd5fe1e958e1a95fbd13","0d49ceb356f7d4735c63bd0d5c7e67665ec7f80c","2e7964d59cd24d1fd2aa4d6a5f93b7f09ea96947")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_sha1 Processes.parent_process_name Processes.parent_process 
| `drop_dm_object_name(Processes)` 
| append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("f77738448eec70113cf711656914b61905b3bd47","b9faa60f85f6f780a34b8d0faaf45b3e3966fdda","3c615ac0f29e743eda8863377f9776619fd2db76","c19401b2f58dc6d2632cb473d44be98dd8292a93","4209dcadeaea6a7df69262fef1beeda940881d4d","61fbe20b7589e6b61eedcd5fe1e958e1a95fbd13","0d49ceb356f7d4735c63bd0d5c7e67665ec7f80c","2e7964d59cd24d1fd2aa4d6a5f93b7f09ea96947")) OR (Filesystem.file_name="trivy" OR Filesystem.file_name="trivy.exe") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash 
| `drop_dm_object_name(Filesystem)` ] 
| sort - firstTime
```

**Defender KQL:**
```kql
let bad_sha1 = dynamic([
  "f77738448eec70113cf711656914b61905b3bd47",
  "b9faa60f85f6f780a34b8d0faaf45b3e3966fdda",
  "3c615ac0f29e743eda8863377f9776619fd2db76",
  "c19401b2f58dc6d2632cb473d44be98dd8292a93",
  "4209dcadeaea6a7df69262fef1beeda940881d4d",
  "61fbe20b7589e6b61eedcd5fe1e958e1a95fbd13",
  "0d49ceb356f7d4735c63bd0d5c7e67665ec7f80c",
  "2e7964d59cd24d1fd2aa4d6a5f93b7f09ea96947"]);
union isfuzzy=true
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (bad_sha1) or InitiatingProcessSHA1 in (bad_sha1)
  | project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath, SHA1, SHA256,
            ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine ),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (bad_sha1)
      or (FileName in~ ("trivy","trivy.exe") and ActionType in ("FileCreated","FileModified"))
  | project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA1, SHA256,
            InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName )
| order by Timestamp desc
```

### [LLM] GitHub Actions runner credential stealer: python3 base64-decoded payload reading /proc/<pid>/mem

`UC_325_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parent_cmds from datamodel=Endpoint.Processes where Processes.process_name IN ("python3","python") AND Processes.parent_process_name IN ("bash","sh","dash","entrypoint.sh","Runner.Worker","node") AND (Processes.process="*base64.b64decode*" OR Processes.process="*base64 -d*" OR Processes.process="*/proc/*/mem*" OR Processes.process="*Runner.Worker*" OR Processes.process="*isSecret*" OR Processes.parent_process="*base64 -d*" OR Processes.parent_process="*entrypoint.sh*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| where match(parent_cmds, "(?i)trivy|aquasecurity|setup-trivy|entrypoint\\.sh|base64") OR match(cmdlines, "(?i)/proc/[0-9]+/mem|Runner\\.Worker|isSecret|b64decode") 
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("python3","python")
| where InitiatingProcessFileName in~ ("bash","sh","dash","Runner.Worker","node","entrypoint.sh")
| where ProcessCommandLine has_any ("base64","b64decode","/proc/","Runner.Worker","isSecret")
   or InitiatingProcessCommandLine has_any ("base64 -d","base64 --decode","entrypoint.sh","aquasecurity","trivy")
| extend mem_read = iff(ProcessCommandLine matches regex @"/proc/\d+/mem", "yes", "")
| extend b64_pipe = iff(InitiatingProcessCommandLine has "base64" and InitiatingProcessCommandLine has "python", "yes", "")
| extend ci_context = iff(InitiatingProcessCommandLine has_any ("entrypoint.sh","aquasecurity","trivy","GITHUB_ACTIONS","RUNNER_") or InitiatingProcessFolderPath has_any ("/runner/","/_work/","/_actions/","/home/runner/"), "yes", "")
| where mem_read == "yes" or b64_pipe == "yes" or ci_context == "yes"
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          mem_read, b64_pipe, ci_context
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — Trivy Compromised a Second Time - Malicious v0.69.4 Release, aquasecurity/setup-

`UC_325_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Trivy Compromised a Second Time - Malicious v0.69.4 Release, aquasecurity/setup- ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("entrypoint.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/local/bin/trivy*" OR Filesystem.file_name IN ("entrypoint.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Trivy Compromised a Second Time - Malicious v0.69.4 Release, aquasecurity/setup-
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("entrypoint.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/local/bin/trivy") or FileName in~ ("entrypoint.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `scan.aquasecurtiy.org`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
