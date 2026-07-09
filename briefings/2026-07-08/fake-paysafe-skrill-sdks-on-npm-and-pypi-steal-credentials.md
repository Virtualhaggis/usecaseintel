# [HIGH] Fake Paysafe, Skrill SDKs on NPM and PyPi steal credentials

**Source:** BleepingComputer
**Published:** 2026-07-08
**Article:** https://www.bleepingcomputer.com/news/security/fake-paysafe-skrill-sdks-on-npm-and-pypi-steal-credentials/

## Threat Profile

Fake Paysafe, Skrill SDKs on NPM and PyPi steal credentials 
By Bill Toulas 
July 8, 2026
03:54 PM
0 
Malicious packages on the Node Package Manager (npm) and the Python Package Index (PyPI) delivered stealer malware to developers and users of Paysafe, Skrill, and Neteller payment applications.
The threat actor published at least 17 malicious packages simultaneously, each tasked to exfiltrate credentials and access tokens to a command-and-control server hosted on Amazon Web Services (AWS).
All t…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `caliber-spinner-finishing.ngrok-free.dev`
- **SHA256:** `ce09810adca70ebec87bc455380ef629ceaa2a0d926149d9115604060167682c`
- **SHA256:** `c6af37a6739f0d919ab7049caf3a85831cab44bdbea27e0d9de7adec80334e2b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1204.003** — User Execution: Malicious Image / Package
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Install of fake Paysafe/Skrill/Neteller npm & PyPI credential-stealer packages

`UC_24_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm","node.exe","pip.exe","pip3.exe","python.exe","python3.exe","yarn.exe","pnpm.exe")) AND (Processes.process="*paysafe-checkout*" OR Processes.process="*paysafe-vault*" OR Processes.process="*paysafe-js*" OR Processes.process="*paysafe-api*" OR Processes.process="*paysafe-node*" OR Processes.process="*paysafe-cards*" OR Processes.process="*paysafe-fraud*" OR Processes.process="*paysafe-kyc*" OR Processes.process="*paysafe-payments*" OR Processes.process="*paysafe-sdk*" OR Processes.process="*skrill-payments*" OR Processes.process="*skrill-sdk*" OR Processes.process="*skrill*" OR Processes.process="*neteller*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","npm","node.exe","pip.exe","pip3.exe","python.exe","python3.exe","yarn.exe","pnpm.exe")
| where ProcessCommandLine has_any ("paysafe-checkout","paysafe-vault","paysafe-js","paysafe-api","paysafe-node","paysafe-cards","paysafe-fraud","paysafe-kyc","paysafe-payments","paysafe-sdk","skrill-payments","skrill-sdk","skrill","neteller")
| where ProcessCommandLine has_any ("install","add"," i ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### C2 exfil to Paysafe-stealer ngrok endpoint caliber-spinner-finishing.ngrok-free.dev

`UC_24_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*caliber-spinner-finishing.ngrok-free.dev*" by DNS.src DNS.dest DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "caliber-spinner-finishing.ngrok-free.dev"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `caliber-spinner-finishing.ngrok-free.dev`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ce09810adca70ebec87bc455380ef629ceaa2a0d926149d9115604060167682c`, `c6af37a6739f0d919ab7049caf3a85831cab44bdbea27e0d9de7adec80334e2b`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
