# [HIGH] GitHub Breached — Employee Device Hack Led to Exfiltration of 3,800+ Internal Repos

**Source:** The Hacker News, BleepingComputer, Cyber Security News, StepSecurity
**Published:** 2026-05-20
**Article:** https://thehackernews.com/2026/05/github-investigating-teampcp-claimed.html

## Threat Profile

Back to Blog Threat Intel Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack Three malicious versions of Microsoft's official durabletask Python SDK were published to PyPI on May 19, 2026. The compromised package silently downloads and executes a 28 KB payload that steals credentials from AWS, Azure, GCP, Kubernetes, password managers, and over 90 developer tool configurations, then spreads laterally through cloud infrastructure. The payload skips systems with a Russian loca…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `185.95.159.32`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `git-service.com`
- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `m-kosche.com`
- **SHA256:** `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`
- **SHA256:** `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`
- **SHA256:** `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`
- **SHA256:** `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`
- **SHA256:** `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`
- **SHA256:** `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`
- **SHA256:** `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
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

`UC_11_8` · phase: **c2** · confidence: **High**

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

`UC_11_9` · phase: **c2** · confidence: **High**

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

`UC_11_10` · phase: **delivery** · confidence: **High**

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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

### Article-specific behavioural hunt — GitHub Breached — Employee Device Hack Led to Exfiltration of 3,800+ Internal Re

`UC_11_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GitHub Breached — Employee Device Hack Led to Exfiltration of 3,800+ Internal Re ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py","task.py","roulette.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/managed.pyz*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/etc/timezone*" OR Filesystem.file_path="*/usr/bin/pgmonitor.py*" OR Filesystem.file_name IN ("__init__.py","task.py","roulette.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — GitHub Breached — Employee Device Hack Led to Exfiltration of 3,800+ Internal Re
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py", "task.py", "roulette.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/managed.pyz", "/dev/null", "/etc/timezone", "/usr/bin/pgmonitor.py") or FileName in~ ("__init__.py", "task.py", "roulette.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `160.119.64.3`, `185.95.159.32`, `check.git-service.com`, `git-service.com`, `t.m-kosche.com`, `m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
