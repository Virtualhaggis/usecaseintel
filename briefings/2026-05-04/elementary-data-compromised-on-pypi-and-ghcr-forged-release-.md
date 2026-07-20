# [HIGH] elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub Actions Script Injection

**Source:** StepSecurity
**Published:** 2026-05-04
**Article:** https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection

## Threat Profile

Back to Blog Threat Intel elementary-data Compromised on PyPI and GHCR: Forged Release Pushed via GitHub Actions Script Injection A malicious version of elementary-data (0.23.3) was published to PyPI and is, at the time of writing, still listed as the latest release. The same release run also pushed a multi-arch container image to GitHub Container Registry at ghcr.io/elementary-data/elementary, tagged both 0.23.3 and latest. Varun Sharma View LinkedIn April 25, 2026
Share on X Share on X Share o…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1546** — Event Triggered Execution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1610** — Deploy Container
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound to elementary-data exfil C2 igotnofriendsonlineorirl-imgonnakmslmao.sky

`UC_424_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where All_Traffic.dest_host="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud" OR All_Traffic.dest="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud" by All_Traffic.src host All_Traffic.app | `drop_dm_object_name(All_Traffic)` | appendpipe [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.dest) as dest from datamodel=Web where Web.url="*igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud*" OR Web.dest="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud" by Web.src host Web.http_method | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MaliciousDomain = "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud";
let WindowDays = 30d;
union isfuzzy=true
    (DeviceNetworkEvents
        | where Timestamp > ago(WindowDays)
        | where RemoteUrl has MaliciousDomain
        | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Source = "DeviceNetworkEvents"),
    (DeviceEvents
        | where Timestamp > ago(WindowDays)
        | where ActionType == "DnsQueryResponse"
        | where AdditionalFields has MaliciousDomain or RemoteUrl has MaliciousDomain
        | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort = toint(0), Source = "DeviceEvents(DNS)")
| order by Timestamp desc
```

### Malicious elementary.pth dropped in Python site-packages

`UC_424_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process_name values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where (Filesystem.file_name="elementary.pth") AND (Filesystem.file_path="*site-packages*" OR Filesystem.file_path="*dist-packages*") by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName =~ "elementary.pth"
| where FolderPath has_any ("\\site-packages\\", "/site-packages/", "/dist-packages/")
| extend IsOversized = (FileSize > 50000)  // legit .pth files are <1KB; payload is ~245KB
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, IsOversized,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Install of trojaned elementary-data 0.23.3 via pip / poetry / uv

`UC_424_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","poetry","poetry.exe","uv","uv.exe","python.exe","python3","python")) AND (Processes.process="*elementary-data==0.23.3*" OR Processes.process="*elementary-data 0.23.3*" OR Processes.process="*elementary_data-0.23.3*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pip.exe", "pip3.exe", "pip", "pip3", "poetry.exe", "poetry", "uv.exe", "uv", "python.exe", "python3", "python")
   or InitiatingProcessFileName in~ ("pip.exe", "pip3.exe", "poetry.exe", "uv.exe")
| where ProcessCommandLine has "elementary-data"
| where ProcessCommandLine has_any ("==0.23.3", " 0.23.3", "elementary_data-0.23.3", "elementary-data-0.23.3")
   or (ProcessCommandLine has "elementary-data" and ProcessCommandLine has_any ("install", "add", "sync") and not(ProcessCommandLine has "==0.23.4" or ProcessCommandLine has "<0.23.3"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Docker / Kubernetes pull of compromised ghcr.io/elementary-data/elementary image

`UC_424_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("docker.exe","docker","podman","podman.exe","crictl","crictl.exe","kubectl","kubectl.exe","nerdctl","nerdctl.exe","buildah","skopeo")) AND Processes.process="*ghcr.io/elementary-data/elementary*" AND (Processes.process="*pull*" OR Processes.process="*run*" OR Processes.process="*create*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("docker.exe", "docker", "podman.exe", "podman", "crictl.exe", "crictl", "kubectl.exe", "kubectl", "nerdctl.exe", "nerdctl", "buildah", "skopeo")
| where ProcessCommandLine has "ghcr.io/elementary-data/elementary"
| extend IsLatestOrBad = ProcessCommandLine has_any (":latest", ":0.23.3", "sha256:31ecc5939de6") or not(ProcessCommandLine matches regex @":(0\.23\.[4-9]|0\.2[4-9]|[1-9])")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, IsLatestOrBad
| order by Timestamp desc
```

### Stage-3 exfil archive trin.tar.gz POST via curl --data-binary

`UC_424_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("curl","curl.exe") AND Processes.process="*--data-binary*" AND (Processes.process="*skyhanni.cloud*" OR Processes.process="*trin.tar.gz*") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`) | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where Filesystem.file_name="trin.tar.gz" by Filesystem.dest Filesystem.file_name | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let WindowDays = 30d;
let C2 = "igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud";
union isfuzzy=true
    (DeviceProcessEvents
        | where Timestamp > ago(WindowDays)
        | where FileName in~ ("curl", "curl.exe")
        | where ProcessCommandLine has "--data-binary"
        | where ProcessCommandLine has_any (C2, "trin.tar.gz", "X-Rise-To-The-Trinny")
        | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, Source = "ProcessExec"),
    (DeviceFileEvents
        | where Timestamp > ago(WindowDays)
        | where ActionType in ("FileCreated", "FileModified")
        | where FileName =~ "trin.tar.gz"
        | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine = strcat(FolderPath, "\\", FileName), Source = "FileWrite")
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

`UC_424_5` · phase: **install** · confidence: **High**

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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
