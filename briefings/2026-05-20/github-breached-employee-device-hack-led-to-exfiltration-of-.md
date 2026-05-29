# [HIGH] GitHub Breached — Employee Device Hack Led to Exfiltration of 3,800+ Internal Repos

**Source:** The Hacker News, Aikido
**Published:** 2026-05-20
**Article:** https://thehackernews.com/2026/05/github-investigating-teampcp-claimed.html

## Threat Profile

GitHub Investigating TeamPCP Claimed Breach of ~4,000 Internal Repositories 
 Ravie Lakshmanan  May 20, 2026 Malware / Cloud Security 
GitHub on Tuesday said it's investigating unauthorized access to its internal repositories after the notorious threat actor known as TeamPCP listed the platform's source code and internal organizations for sale on a cybercrime forum.
"While we currently have no evidence of impact to customer information stored outside of GitHub's internal repositories (such as …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `185.95.159.32`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `git-service.com`
- **Domain (defanged):** `m-kosche.com`
- **SHA256:** `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`
- **SHA256:** `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`
- **SHA256:** `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`
- **SHA256:** `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1176** — Browser Extensions
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1566.002** — Phishing: Spearphishing Link
- **T1598.003** — Phishing for Information: Spearphishing Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Browser contact with Trust Wallet impostor analytics domain (metrics-trustwallet.com)

`UC_126_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Traffic.app) as app values(Network_Traffic.src) as src values(Network_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (Network_Traffic.dest="metrics-trustwallet.com" OR Network_Traffic.dest="api.metrics-trustwallet.com" OR Network_Traffic.dest_url="*metrics-trustwallet.com*") by Network_Traffic.src host Network_Traffic.user | `drop_dm_object_name(Network_Traffic)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (Network_Resolution.DNS.query="metrics-trustwallet.com" OR Network_Resolution.DNS.query="api.metrics-trustwallet.com") by Network_Resolution.DNS.src Network_Resolution.DNS.query | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badHosts = dynamic(["metrics-trustwallet.com", "api.metrics-trustwallet.com"]);
let net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (badHosts)
       or tolower(RemoteUrl) endswith "metrics-trustwallet.com"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, ActionType, ReportId;
let dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where AdditionalFields has_any (badHosts)
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, AdditionalFields, ActionType, ReportId;
union isfuzzy=true net, dns
| order by Timestamp desc
```

### [LLM] Shai-Hulud npm worm C2 callback to websocket-api2.publicvm.com

`UC_126_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(`cim_Network_Resolution_indexes` OR `cim_Network_Traffic_indexes`) (query="websocket-api2.publicvm.com" OR dest="websocket-api2.publicvm.com" OR url="*websocket-api2.publicvm.com*")
| eval ioc="websocket-api2.publicvm.com"
| stats count min(_time) as firstTime max(_time) as lastTime values(src) as src values(user) as user values(process_name) as process_name values(dest_port) as dest_port by host ioc
| convert ctime(firstTime) ctime(lastTime)
| append [| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.process_name="node.exe" OR Processes.process_name="npm.exe" OR Processes.process_name="npx.exe" OR Processes.process_name="yarn.exe" OR Processes.process_name="pnpm.exe") (Processes.process="*postinstall*" OR Processes.process="*npm install*" OR Processes.process="*npm publish*") by Processes.host Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let ioc = "websocket-api2.publicvm.com";
let net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has ioc
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, ReportId;
let dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | where AdditionalFields has ioc
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, AdditionalFields, ReportId;
let nodeProc = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("node.exe", "npm.exe", "npx.exe", "yarn.exe", "pnpm.exe") or FileName in~ ("node.exe", "npm.exe", "npx.exe")
    | where ProcessCommandLine has_any ("postinstall", "preinstall", "prepare")
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, AccountName, FileName, ReportId;
union isfuzzy=true net, dns
| join kind=leftouter (nodeProc | project Timestamp, DeviceName, NodeCmd = ProcessCommandLine) on DeviceName
| where isempty(Timestamp1) or abs(datetime_diff('second', Timestamp, Timestamp1)) < 600
| project-away Timestamp1, DeviceName1
| order by Timestamp desc
```

### [LLM] npm credential phishing typosquat domain visit (npmjs.help)

`UC_126_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.http_user_agent) as ua values(Web.url) as url from datamodel=Web.Web where (Web.url="*npmjs.help*" OR Web.dest="npmjs.help") by Web.site
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="npmjs.help" by DNS.src DNS.query | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
let ioc = "npmjs.help";
let clicks = UrlClickEvents
    | where Timestamp > ago(30d)
    | where Url has ioc
    | project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress, ReportId;
let net = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has ioc
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP, ReportId;
let dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse" and AdditionalFields has ioc
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields, ReportId;
let mail = EmailUrlInfo
    | where Timestamp > ago(30d)
    | where Url has ioc or UrlDomain =~ ioc
    | join kind=inner (EmailEvents | project NetworkMessageId, Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction) on NetworkMessageId
    | project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, Url, DeliveryAction, ReportId;
union isfuzzy=true clicks, net, dns, mail
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
  - IP / domain IOC(s): `160.119.64.3`, `185.95.159.32`, `check.git-service.com`, `t.m-kosche.com`, `git-service.com`, `m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`, `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
