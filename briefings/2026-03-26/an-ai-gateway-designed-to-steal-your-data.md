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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1568** — Dynamic Resolution
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1611** — Escape to Host
- **T1610** — Deploy Container
- **T1053.006** — Scheduled Task/Job: Systemd Timers

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] LiteLLM/TeamPCP C2 beacon to checkmarx.zone/raw and models.litellm.cloud

`UC_158_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user_agent) as user_agents from datamodel=Web where Web.url IN ("*checkmarx.zone/raw*","*checkmarx.zone/static/checkmarx-util*","*checkmarx.zone/static/*.tgz","*models.litellm.cloud*") OR Web.dest IN ("checkmarx.zone","models.litellm.cloud") by Web.src Web.dest Web.http_method | `drop_dm_object_name(Web)` | append [| tstats summariesonly=true count from datamodel=Network_Resolution where Network_Resolution.DNS.query IN ("checkmarx.zone","*.checkmarx.zone","models.litellm.cloud") by Network_Resolution.DNS.src Network_Resolution.DNS.query | `drop_dm_object_name(Network_Resolution.DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where RemoteUrl has_any ("checkmarx.zone/raw","checkmarx.zone/static/checkmarx-util","models.litellm.cloud")
     or RemoteUrl matches regex @"checkmarx\.zone/static/.*\.tgz"
  | project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName ),
( DeviceEvents
  | where ActionType == "DnsQueryResponse" and AdditionalFields has_any ("checkmarx.zone","models.litellm.cloud")
  | project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName )
| sort by Timestamp desc
```

### [LLM] Trojanised LiteLLM dropper artefacts (litellm_init.pth, p.py, session.key, tpcp.tar.gz)

`UC_158_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_id) as pids from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("litellm_init.pth","p.py","session.key","tpcp.tar.gz")) OR (Filesystem.file_path="*site-packages/litellm/proxy/proxy_server.py" AND Filesystem.action="modified") by host Filesystem.dest Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | stats dc(file_name) as distinct_artifacts values(file_name) as artifacts values(paths) as paths min(firstTime) as firstTime max(lastTime) as lastTime by host dest user | where distinct_artifacts>=2 OR match(artifacts,"litellm_init\.pth|tpcp\.tar\.gz") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where FileName in~ ("litellm_init.pth","p.py","session.key","tpcp.tar.gz")
   or (FileName == "proxy_server.py" and FolderPath has "site-packages/litellm/proxy" and ActionType == "FileModified")
| extend Artifact = FileName
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Artifacts=make_set(Artifact), Paths=make_set(FolderPath), Procs=make_set(InitiatingProcessFileName), Cmds=make_set(InitiatingProcessCommandLine) by DeviceId, DeviceName, InitiatingProcessAccountName
| where array_length(Artifacts) >= 2 or Artifacts has_any ("litellm_init.pth","tpcp.tar.gz")
```

### [LLM] TeamPCP sysmon.py systemd persistence and Kubernetes node foothold

`UC_158_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_path) as parent_proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.config/sysmon/sysmon.py","/root/.config/sysmon/sysmon.py","/tmp/.pg_state","/tmp/pglog")) OR (Filesystem.file_path IN ("/etc/systemd/system/sysmon.service","*/.config/systemd/user/sysmon.service")) by host Filesystem.dest Filesystem.file_name Filesystem.user | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process IN ("*systemctl* enable *sysmon*","*systemctl* start *sysmon*","*chmod +x /tmp/pglog*","*kubectl* create *--privileged*") by host Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceFileEvents
  | where (FolderPath endswith "/.config/sysmon" and FileName == "sysmon.py")
       or (FolderPath in ("/tmp","/tmp/") and FileName in ("pglog",".pg_state"))
       or (FileName == "sysmon.service" and FolderPath has_any ("/etc/systemd/system","/.config/systemd/user"))
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName ),
( DeviceProcessEvents
  | where ProcessCommandLine has_any ("systemctl enable sysmon","systemctl start sysmon","chmod +x /tmp/pglog")
       or (ProcessCommandLine has "kubectl" and ProcessCommandLine has_all ("--privileged","hostPath"))
  | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName )
| sort by Timestamp desc
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
| where FolderPath has_any ("\Ethereum\keystore\","\Bitcoin\","\Exodus\","\Electrum\wallets\","\MetaMask\","\Phantom\","\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — An AI gateway designed to steal your data

`UC_158_6` · phase: **exploit** · confidence: **High**

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

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
