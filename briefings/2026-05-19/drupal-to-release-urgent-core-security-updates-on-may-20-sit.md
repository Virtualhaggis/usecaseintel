# [HIGH] Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare

**Source:** The Hacker News, BleepingComputer, Aikido, StepSecurity, GitHub Security Advisories
**Published:** 2026-05-19
**Article:** https://thehackernews.com/2026/05/drupal-to-release-urgent-core-security.html

## Threat Profile

Back to Blog Threat Intel Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack Three malicious versions of Microsoft's official durabletask Python SDK were published to PyPI on May 19, 2026. The compromised package silently downloads and executes a 28 KB payload that steals credentials from AWS, Azure, GCP, Kubernetes, password managers, and over 90 developer tool configurations, then spreads laterally through cloud infrastructure. The payload skips systems with a Russian loca…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `83.142.209.194`
- **IPv4 (defanged):** `185.95.159.32`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `git-service.com`
- **Domain (defanged):** `m-kosche.com`
- **SHA256:** `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`
- **SHA256:** `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`
- **SHA256:** `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`
- **SHA256:** `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`
- **SHA256:** `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`
- **SHA256:** `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`
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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] durabletask C2 contact — check.git-service.com / t.m-kosche.com from python3

`UC_12_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.src_ip) as src_ip values(DNS.query) as query from datamodel=Network_Resolution.DNS where (DNS.query="check.git-service.com" OR DNS.query="*.git-service.com" OR DNS.query="t.m-kosche.com" OR DNS.query="*.m-kosche.com") by DNS.src DNS.src_ip DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*git-service.com*" OR Web.url="*m-kosche.com*" OR Web.dest_ip="160.119.64.3" OR Web.dest_ip="83.142.209.194" OR Web.dest_ip="185.95.159.32") by Web.src Web.src_ip Web.url Web.dest_ip | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
// TeamPCP Mini Shai-Hulud — durabletask supply chain C2
let badDomains = dynamic(["check.git-service.com","git-service.com","t.m-kosche.com","m-kosche.com"]);
let badIPs = dynamic(["160.119.64.3","83.142.209.194","185.95.159.32"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (badDomains) or RemoteIP in (badIPs)
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

### [LLM] python3 dropping and detached-spawning /tmp/managed.pyz (durabletask rope.pyz dropper)

`UC_12_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.process_hash) as hashes values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name=python3* AND (Processes.process="*/tmp/managed.pyz*" OR Processes.process_name="managed.pyz" OR Processes.process_hash IN ("069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce","7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8","aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5","877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec","3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf","85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f","c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc")) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// durabletask dropper — python3 spawning /tmp/managed.pyz with detached session
let badHashes = dynamic([
  "069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce",
  "7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8",
  "aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5",
  "877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec",
  "3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf",
  "85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f",
  "c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc"
]);
let procs = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has "/tmp/managed.pyz"
       or FolderPath has "/tmp/managed.pyz"
       or SHA256 in (badHashes)
       or (InitiatingProcessFileName has "python" and FileName =~ "managed.pyz")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath,
              ProcessCommandLine, SHA256, ProcessId,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName, ReportId;
let files = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath == "/tmp/managed.pyz" or FileName =~ "managed.pyz" or SHA256 in (badHashes)
    | where InitiatingProcessFileName has_any ("python","python3","python3.14")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, ReportId;
union procs, files
| order by Timestamp desc
```

### [LLM] GitHub token exfiltration — `gh auth token` / `gh auth status --show-token` spawned by python3

`UC_12_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="gh" AND Processes.parent_process_name IN ("python3","python3.14","python") AND (Processes.process="*auth token*" OR Processes.process="*auth status*--show-token*") by host Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// rope.pyz credential exfil — gh CLI spawned by python3 to dump GitHub tokens
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "gh"
| where ProcessCommandLine has_any ("auth token", "auth status --show-token", "auth status -t")
| where InitiatingProcessFileName has "python"
   or InitiatingProcessParentFileName has "python"
   or InitiatingProcessCommandLine has "/tmp/managed.pyz"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessParentId,
          ProcessId, ReportId
| order by Timestamp desc
```

### [LLM] Fake pgsql-monitor systemd persistence dropped by python3

`UC_12_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All.process) as cmd values(All.user) as user from datamodel=Endpoint where (Endpoint.Processes.process="*systemctl*--user*daemon-reload*" AND Endpoint.Processes.parent_process_name IN ("python3","python3.14","python")) OR (Endpoint.Filesystem.file_path="*/.config/systemd/user/pgsql-monitor.service*" OR Endpoint.Filesystem.file_name="pgsql-monitor.service") by host Endpoint.Processes.parent_process | `drop_dm_object_name(All)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// rope.pyz persistence — pgsql-monitor.service systemd unit + python-triggered daemon-reload
let svcWrite = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "pgsql-monitor.service"
       or FolderPath has "/.config/systemd/user/pgsql-monitor"
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId;
let daemonReload = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "systemctl"
    | where ProcessCommandLine has "--user" and ProcessCommandLine has "daemon-reload"
    | where InitiatingProcessFileName has "python"
       or InitiatingProcessCommandLine has "/tmp/managed.pyz"
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId;
union svcWrite, daemonReload
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

### Article-specific behavioural hunt — Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare

`UC_12_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare ```
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
// Article-specific bespoke detection — Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare
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
  - IP / domain IOC(s): `160.119.64.3`, `83.142.209.194`, `185.95.159.32`, `check.git-service.com`, `t.m-kosche.com`, `git-service.com`, `m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`, `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
