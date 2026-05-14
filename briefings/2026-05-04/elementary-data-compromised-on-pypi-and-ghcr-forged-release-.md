# [HIGH] elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub Actions Script Injection

**Source:** StepSecurity
**Published:** 2026-05-04
**Article:** https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection

## Threat Profile

Back to Blog Threat Intel elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub Actions Script Injection A malicious version of elementary-data (0.23.3) was published to PyPI and is, at the time of writing, still listed as the latest release. The same release run also pushed a multi-arch container image to GitHub Container Registry at ghcr.io/elementary-data/elementary, tagged both 0.23.3 and latest. Varun Sharma View LinkedIn April 25, 2026
Share on X Share on X Share o…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255`
- **SHA256:** `b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9`
- **SHA1:** `b1e4b1f3aad0d489ab0e9208031c67402bbb8480`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1041** — Exfiltration Over C2 Channel
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1505.003** — Server Software Component: Web Shell
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Local Data Staging
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] elementary-data malicious release C2 callback to skyhanni.cloud

`UC_207_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.src_ip) as src_ip values(All_Traffic.app) as app from datamodel=Network_Traffic where (All_Traffic.dest="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud" OR All_Traffic.dest_host="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud" OR All_Traffic.url="*skyhanni.cloud*") by All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.action | `drop_dm_object_name("All_Traffic")` | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.src_ip) as src_ip from datamodel=Network_Resolution where DNS.query="*skyhanni.cloud" by DNS.query DNS.dest DNS.reply_code | `drop_dm_object_name("DNS")`] | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.http_user_agent) as ua values(Web.http_method) as method from datamodel=Web where (Web.url="*skyhanni.cloud*" OR Web.dest="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud") by Web.url Web.dest | `drop_dm_object_name("Web")`] | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
// elementary-data 0.23.3 stealer — exfil to skyhanni.cloud
let C2Domain = "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud";
let C2Parent = "skyhanni.cloud";
// 1) Direct TCP/HTTP egress to the C2 host
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl =~ C2Domain or RemoteUrl endswith strcat(".", C2Parent) or RemoteUrl endswith C2Parent
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, Source="NetworkEvent")
| union
// 2) DNS resolution for the C2 host (DeviceEvents DnsQueryResponse)
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| extend Q = tostring(parse_json(AdditionalFields).QueryName)
| where Q endswith C2Parent
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP="", RemotePort=int(null), RemoteUrl=Q,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath="",
          InitiatingProcessAccountName, Source="DnsQuery")
| order by Timestamp desc
```

### [LLM] Trojaned elementary-data 0.23.3 wheel / GHCR image inventory

`UC_207_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.user) as users from datamodel=Endpoint.Filesystem where (Filesystem.file_name="elementary.pth" OR Filesystem.file_path="*site-packages*elementary.pth" OR Filesystem.file_path="*elementary_data-0.23.3*" OR Filesystem.file_path="*elementary-data-0.23.3*" OR Filesystem.file_hash="31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255") by host Filesystem.file_name | `drop_dm_object_name("Filesystem")` | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as processes from datamodel=Endpoint.Processes where (Processes.process="*pip*install*elementary-data*0.23.3*" OR Processes.process="*docker*pull*ghcr.io/elementary-data/elementary*" OR Processes.process="*ghcr.io/elementary-data/elementary:0.23.3*" OR Processes.process="*ghcr.io/elementary-data/elementary:latest*") by host Processes.user | `drop_dm_object_name("Processes")`] | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
// elementary-data 0.23.3 — exposure inventory across endpoints + CI runners
let BadVersion = "0.23.3";
let BadImageDigest = "31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255";
// (a) TVM software inventory shows elementary-data 0.23.3 installed
(DeviceTvmSoftwareInventory
| where SoftwareName has "elementary" and SoftwareVersion == BadVersion
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, Source="TvmInventory")
| union
// (b) File-event evidence — elementary.pth dropped in site-packages, or wheel/sdist with 0.23.3 in path
(DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "elementary.pth" and FolderPath has "site-packages")
     or FolderPath has_any ("elementary_data-0.23.3", "elementary-data-0.23.3")
     or SHA256 == BadImageDigest
| project Timestamp, DeviceName, DeviceId, OSPlatform="", SoftwareVendor="",
          SoftwareName=FileName, SoftwareVersion=FolderPath, Source="FileEvent")
| union
// (c) Process evidence — pip / docker / kubectl pulling the malicious artefact
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName in~ ("pip.exe","pip3.exe","pip","pip3","python.exe","python3","python") and ProcessCommandLine has "elementary-data" and ProcessCommandLine has "0.23.3")
     or (FileName in~ ("docker.exe","docker","podman","crane","skopeo","ctr","nerdctl") and ProcessCommandLine has "ghcr.io/elementary-data/elementary")
     or ProcessCommandLine has "ghcr.io/elementary-data/elementary:0.23.3"
     or ProcessCommandLine has BadImageDigest
| project Timestamp, DeviceName, DeviceId, OSPlatform="", SoftwareVendor=InitiatingProcessFileName,
          SoftwareName=FileName, SoftwareVersion=ProcessCommandLine, Source="ProcessEvent")
| order by Timestamp desc
```

### [LLM] elementary-data stealer host-side artefacts: trin.tar.gz, .trinny-security-update marker

`UC_207_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_name="trin.tar.gz" OR Filesystem.file_name=".trinny-security-update" OR Filesystem.file_path="*\\Temp\\trin.tar.gz" OR Filesystem.file_path="*/tmp/trin.tar.gz" OR Filesystem.file_path="*/tmp/.trinny-security-update" OR Filesystem.file_path="*\\Temp\\.trinny-security-update") by host Filesystem.file_name Filesystem.action | `drop_dm_object_name("Filesystem")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
// elementary-data stealer host artefacts — trin.tar.gz + .trinny-security-update
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("trin.tar.gz", ".trinny-security-update")
     or FolderPath endswith @"\Temp\trin.tar.gz"
     or FolderPath endswith "/tmp/trin.tar.gz"
     or FolderPath endswith "/tmp/.trinny-security-update"
     or FolderPath endswith @"\Temp\.trinny-security-update"
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
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

### Article-specific behavioural hunt — elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub A

`UC_207_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub A ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/kubernetes/*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_path="*/var/log/auth.log*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub A
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/kubernetes/", "/etc/passwd", "/etc/shadow", "/var/log/auth.log"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255`, `b3bbfafde1a0db3a4d47e70eb0eb2ca19daef4a19410154a71abee567b35d3d9`, `b1e4b1f3aad0d489ab0e9208031c67402bbb8480`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
