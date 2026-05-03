# [HIGH] An AI gateway designed to steal your data

**Source:** Securelist (Kaspersky)
**Published:** 2026-03-26
**Article:** https://securelist.com/litellm-supply-chain-attack/119257/

## Threat Profile

Table of Contents
Repository compromise 
Technical analysis 
OpenVSX version of the malware 
Victimology 
Conclusion 
Prevention and protection 
Indicators of Compromise: 
Authors
Vladimir Gursky 
A significant proportion of cyberincidents are linked to supply chain attacks, and this proportion is constantly growing. Over the past year, we have seen a wide variety of methods used in such attacks, ranging from creation of malicious but seemingly legitimate open-source libraries or delayed attacks…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `models.litellm.cloud`
- **MD5:** `85ED77A21B88CAE721F369FA6B7BBBA3`
- **MD5:** `2E3A4412A7A487B32C5715167C755D08`
- **MD5:** `0FCCC8E3A03896F45726203074AE225D`
- **MD5:** `F5560871F6002982A6A2CC0B3EE739F7`
- **MD5:** `CDE4951BEE7E28AC8A29D33D34A41AE5`
- **MD5:** `05BACBE163EF0393C2416CBD05E45E74`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms (typosquat variant)
- **T1041** — Exfiltration Over C2 Channel
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TeamPCP sysmon.py systemd persistence drop on Linux / Kubernetes node

`UC_157_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") AND Filesystem.file_name="sysmon.py" AND (Filesystem.file_path="*/.config/sysmon/sysmon.py" OR Filesystem.file_path="/root/.config/sysmon/sysmon.py") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// TeamPCP sysmon.py systemd persistence — LiteLLM / Checkmarx supply chain, March 2026
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "sysmon.py"
| where FolderPath has @"/.config/sysmon"           // matches both /root/.config/sysmon and /home/<u>/.config/sysmon
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] TeamPCP C2 callback to checkmarx[.]zone or models[.]litellm[.]cloud

`UC_157_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("checkmarx.zone","models.litellm.cloud","*.checkmarx.zone","*.models.litellm.cloud") OR All_Traffic.dest_ip="83.142.209.11") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*checkmarx.zone" OR DNS.query="*models.litellm.cloud") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` ]
```

**Defender KQL:**
```kql
// TeamPCP C2 — checkmarx[.]zone (83.142.209.11) and models[.]litellm[.]cloud
let TeamPCP_Domains = dynamic(["checkmarx.zone","models.litellm.cloud"]);
let TeamPCP_IPs     = dynamic(["83.142.209.11"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has_any (TeamPCP_Domains)) or (RemoteIP in (TeamPCP_IPs))
    | project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessAccountName,
              SourceTable = "DeviceNetworkEvents" ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q has_any (TeamPCP_Domains)
    | project Timestamp, DeviceName, Q, InitiatingProcessFileName,
              InitiatingProcessCommandLine, InitiatingProcessAccountName,
              SourceTable = "DeviceEvents.DnsQueryResponse" )
| order by Timestamp desc
```

### [LLM] Trojanized LiteLLM staging artefacts (p.py / session.key / tpcp.tar.gz) written by Python

`UC_157_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true values(Filesystem.file_name) as artifacts dc(Filesystem.file_name) as artifact_count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND Filesystem.file_name IN ("p.py","session.key","tpcp.tar.gz") AND (Filesystem.process_name IN ("python","python2","python3","uwsgi","gunicorn","uvicorn") OR Filesystem.process="*litellm*" OR Filesystem.process="*proxy_server*") by Filesystem.dest Filesystem.user Filesystem.process_name | where artifact_count >= 2 OR mvfind(artifacts,"tpcp.tar.gz")>=0 | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Trojanized LiteLLM 1.82.7 / 1.82.8 — staging artefacts dropped by python interpreter
let StageArtifacts = dynamic(["p.py","session.key","tpcp.tar.gz"]);
let PyHosts = dynamic(["python","python2","python3","uwsgi","gunicorn","uvicorn"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ (StageArtifacts)
| where InitiatingProcessFileName has_any (PyHosts)
      or InitiatingProcessCommandLine has_any ("litellm","proxy_server","litellm_init.pth")
| summarize ArtifactSet  = make_set(FileName, 16),
            ArtifactCount = dcount(FileName),
            FirstSeen    = min(Timestamp),
            LastSeen     = max(Timestamp),
            DropProc     = any(InitiatingProcessFileName),
            DropCmd      = any(InitiatingProcessCommandLine),
            FolderSet    = make_set(FolderPath, 16)
            by DeviceName, InitiatingProcessAccountName
| where ArtifactCount >= 2 or ArtifactSet has "tpcp.tar.gz"   // tpcp.tar.gz alone is conclusive
| order by LastSeen desc
```

### Beaconing â€” periodic outbound to small set of destinations

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

### Article-specific behavioural hunt — An AI gateway designed to steal your data

`UC_157_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — An AI gateway designed to steal your data ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("proxy_server.py","sysmon.py","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/www*" OR Filesystem.file_path="*/root/.config/sysmon/sysmon.py*" OR Filesystem.file_path="*/tmp/.pg_state*" OR Filesystem.file_path="*/tmp/pglog*" OR Filesystem.file_name IN ("proxy_server.py","sysmon.py","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — An AI gateway designed to steal your data
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("proxy_server.py", "sysmon.py", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/www", "/root/.config/sysmon/sysmon.py", "/tmp/.pg_state", "/tmp/pglog") or FileName in~ ("proxy_server.py", "sysmon.py", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `checkmarx.zone`, `models.litellm.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `85ED77A21B88CAE721F369FA6B7BBBA3`, `2E3A4412A7A487B32C5715167C755D08`, `0FCCC8E3A03896F45726203074AE225D`, `F5560871F6002982A6A2CC0B3EE739F7`, `CDE4951BEE7E28AC8A29D33D34A41AE5`, `05BACBE163EF0393C2416CBD05E45E74`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
