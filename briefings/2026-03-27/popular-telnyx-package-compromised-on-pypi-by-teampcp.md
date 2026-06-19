# [CRIT] Popular telnyx package compromised on PyPI by TeamPCP

**Source:** Aikido
**Published:** 2026-03-27
**Article:** https://www.aikido.dev/blog/telnyx-pypi-compromised-teampcp-canisterworm

## Threat Profile

Blog Vulnerabilities & Threats Popular telnyx package compromised on PyPI by TeamPCP Popular telnyx package compromised on PyPI by TeamPCP Written by Charlie Eriksen Published on: Mar 27, 2026 This morning's telnyx compromise is the latest move in what is now a weeks-long TeamPCP supply chain campaign crossing multiple ecosystems. Trivy. Checkmarx. LiteLLM. And now Telnyx on PyPI, uploaded hours ago at 03:51 UTC on March 27.
The pattern is consistent: steal credentials from a trusted security to…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33634`
- **IPv4 (defanged):** `83.142.209.203`
- **Domain (defanged):** `checkmarx.zone`
- **SHA256:** `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9`
- **SHA256:** `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1547.001** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1027.003** — Steganography
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1140** — Deobfuscate/Decode Files or Information
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Telnyx PyPI compromise: malicious telnyx 4.87.1 / 4.87.2 hash on disk

`UC_444_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9","cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3") OR (Filesystem.file_name="_client.py" AND Filesystem.file_path="*\\telnyx\\*") by host Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in ("7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9","cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3")
   or (FolderPath has @"\telnyx\" and FileName =~ "_client.py")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256, FileOriginUrl
| order by Timestamp desc
```

### TeamPCP C2 egress to 83.142.209.203:8080 (telnyx WAV-stego dropper)

`UC_444_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="83.142.209.203" by All_Traffic.src host All_Traffic.user All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.203"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### TeamPCP WAV-stego payload drop (hangup.wav / ringtone.wav)

`UC_444_11` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_name="hangup.wav" OR Filesystem.file_name="ringtone.wav") by host Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | join host [| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="83.142.209.203" by host | `drop_dm_object_name(All_Traffic)` | rename count as c2_hits | fields host c2_hits] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let WavDrop = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FileName in~ ("hangup.wav","ringtone.wav")
  | project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, FileOriginUrl, FileOriginIP, SHA256;
let C2Hosts = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteIP == "83.142.209.203"
  | distinct DeviceId;
WavDrop
| where FileOriginIP == "83.142.209.203" or FileOriginUrl has "83.142.209.203" or DeviceId in (C2Hosts)
| order by Timestamp desc
```

### TeamPCP msbuild.exe persistence in user Startup folder

`UC_444_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as parent values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("msbuild.exe","msbuild.exe.lock") AND Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*" by host Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("msbuild.exe","msbuild.exe.lock")
| where FolderPath has @"\Start Menu\Programs\Startup\"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FolderPath, FileName, SHA256, FileOriginUrl, FileOriginIP
| order by Timestamp desc
```

### TeamPCP Linux/Mac stdin-piped Python second stage (sys.executable -)

`UC_444_13` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="python" OR Processes.process_name="python3" OR Processes.process_name="python3.11" OR Processes.process_name="python3.12") AND Processes.process IN ("*python3 -","*python -","*python3.* -") AND Processes.parent_process_name IN ("python","python3","python3.11","python3.12") by host Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | join host [| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="83.142.209.203" by host | `drop_dm_object_name(All_Traffic)` | rename count as c2_hits | fields host c2_hits] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PyExecDash = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName matches regex @"^python[0-9.]*$"
  | where ProcessCommandLine matches regex @"(?i)\bpython[0-9.]*\s+-\s*$"
  | where InitiatingProcessFileName matches regex @"(?i)^python[0-9.]*$"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath;
let C2Hit = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteIP == "83.142.209.203"
  | summarize ConnTime = min(Timestamp) by DeviceName;
PyExecDash
| join kind=inner C2Hit on DeviceName
| where abs(datetime_diff('minute', Timestamp, ConnTime)) <= 15
| order by Timestamp desc
```

### TeamPCP tpcp.tar.gz exfil POST signature on egress proxy / WAF

`UC_444_14` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.http_method) as methods from datamodel=Web.Web where Web.dest="83.142.209.203" AND Web.http_method="POST" AND (Web.url="*tpcp.tar.gz*" OR Web.http_user_agent="*tpcp*") by host Web.src Web.dest Web.dest_port Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.203" and RemotePort == 8080
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "tpcp.tar.gz"
    | project DeviceName, ExfilTime = Timestamp, FolderPath, FileName
  ) on DeviceName
| where isnotempty(ExfilTime) or InitiatingProcessFileName matches regex @"(?i)^python[0-9.]*(\.exe)?$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ExfilTime, FolderPath, FileName
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

### Article-specific behavioural hunt — Popular telnyx package compromised on PyPI by TeamPCP

`UC_444_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Popular telnyx package compromised on PyPI by TeamPCP ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("msbuild.exe","_client.py") OR Processes.process_path="*%APPDATA%\Microsoft\Windows\Start*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%APPDATA%\Microsoft\Windows\Start*" OR Filesystem.file_name IN ("msbuild.exe","_client.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Popular telnyx package compromised on PyPI by TeamPCP
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("msbuild.exe", "_client.py") or FolderPath has_any ("%APPDATA%\Microsoft\Windows\Start"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%APPDATA%\Microsoft\Windows\Start") or FileName in~ ("msbuild.exe", "_client.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.203`, `checkmarx.zone`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33634`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9`, `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 15 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
