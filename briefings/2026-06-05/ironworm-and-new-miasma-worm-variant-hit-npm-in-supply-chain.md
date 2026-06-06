# [HIGH] IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks

**Source:** The Hacker News, StepSecurity
**Published:** 2026-06-05
**Article:** https://thehackernews.com/2026/06/ironworm-and-new-miasma-worm-variant.html

## Threat Profile

Back to Blog Threat Intel Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack Three malicious versions of Microsoft's official durabletask Python SDK were published to PyPI on May 19, 2026. The compromised package silently downloads and executes a 28 KB payload that steals credentials from AWS, Azure, GCP, Kubernetes, password managers, and over 90 developer tool configurations, then spreads laterally through cloud infrastructure. The payload skips systems with a Russian loca…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `git-service.com`
- **Domain (defanged):** `t.m-kosche.com`
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
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1564.003** — Hidden Window / Detached Session
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution
- **T1555** — Credentials from Password Stores
- **T1552.001** — Credentials In Files
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1021.007** — Remote Services: Cloud Services
- **T1609** — Container Administration Command
- **T1018** — Remote System Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Installation of compromised Microsoft durabletask PyPI versions 1.4.1-1.4.3

`UC_8_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pip","pip3","python","python3","python3.14") (Processes.process="*durabletask==1.4.1*" OR Processes.process="*durabletask==1.4.2*" OR Processes.process="*durabletask==1.4.3*" OR Processes.process="*durabletask-1.4.1*" OR Processes.process="*durabletask-1.4.2*" OR Processes.process="*durabletask-1.4.3*") by host Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pip","pip3","python3","python3.14","python")
   or FileName in~ ("pip","pip3")
| where ProcessCommandLine has "durabletask"
| where ProcessCommandLine has_any ("1.4.1","1.4.2","1.4.3")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Python urlretrieve download of rope.pyz from check.git-service.com to /tmp/managed.pyz

`UC_8_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="python*" (All_Traffic.dest="check.git-service.com" OR All_Traffic.dest="git-service.com" OR All_Traffic.dest_ip="160.119.64.3") by host All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TimeRange = ago(30d);
let C2 = dynamic(["check.git-service.com","git-service.com"]);
let C2IP = dynamic(["160.119.64.3","83.142.209.194"]);
let Net = DeviceNetworkEvents
    | where Timestamp > TimeRange
    | where InitiatingProcessFileName has_any ("python","python3","python3.14")
    | where RemoteUrl has_any (C2) or RemoteIP in (C2IP);
let Drop = DeviceFileEvents
    | where Timestamp > TimeRange
    | where FolderPath == "/tmp" and FileName =~ "managed.pyz"
    | where InitiatingProcessFileName has_any ("python","python3","python3.14");
union Net, Drop
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] python3 import durabletask spawning detached /tmp/managed.pyz collector swarm

`UC_8_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds dc(Processes.process_id) as child_pids from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") Processes.process="*managed.pyz*" by host Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | where child_pids >= 2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python","python3","python3.14")
| where ProcessCommandLine has "/tmp/managed.pyz"
| summarize ChildPids = dcount(ProcessId), AnyCmd = any(ProcessCommandLine), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ParentCmd = any(InitiatingProcessCommandLine)
          by DeviceId, DeviceName, AccountName, InitiatingProcessId
| where ChildPids >= 2
| order by FirstSeen desc
```

### [LLM] Fake pgsql-monitor.service persistence via systemctl --user daemon-reload from python parent

`UC_8_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") (Processes.process="*systemctl --user daemon-reload*" OR Processes.process_name="systemctl" AND Processes.process="*pgsql-monitor*") by host Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_name="pgsql-monitor.service" by host Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` ]
```

**Defender KQL:**
```kql
let TimeRange = ago(30d);
let Procs = DeviceProcessEvents
    | where Timestamp > TimeRange
    | where InitiatingProcessFileName has_any ("python","python3","python3.14")
    | where (FileName =~ "systemctl" and ProcessCommandLine has "--user" and ProcessCommandLine has "daemon-reload")
        or ProcessCommandLine has "pgsql-monitor"
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source = "process";
let Files = DeviceFileEvents
    | where Timestamp > TimeRange
    | where FileName =~ "pgsql-monitor.service"
       or (FolderPath has "systemd/user" and FileName endswith ".service" and InitiatingProcessFileName has_any ("python","python3","python3.14"))
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName, ProcessCommandLine = InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Source = "file";
union Procs, Files
| order by Timestamp desc
```

### [LLM] GPG batch passphrase 'anon' + gh auth token credential harvesting from python parent

`UC_8_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") ((Processes.process_name="gpg" AND Processes.process="*--batch*--passphrase*anon*--decrypt*") OR (Processes.process_name="gh" AND (Processes.process="*auth token*" OR Processes.process="*auth status --show-token*"))) by host Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python","python3","python3.14")
| where (FileName =~ "gpg" and ProcessCommandLine has "--batch" and ProcessCommandLine has "--passphrase" and ProcessCommandLine has " anon" and ProcessCommandLine has "--decrypt")
   or (FileName =~ "gh" and (ProcessCommandLine has "auth token" or ProcessCommandLine has "auth status --show-token"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] DNS / connection to TeamPCP secondary C2 m-kosche.com

`UC_8_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="m-kosche.com" OR DNS.query="*.m-kosche.com" OR DNS.query="git-service.com" OR DNS.query="*.git-service.com") by host DNS.src DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="160.119.64.3" OR All_Traffic.dest_ip="83.142.209.194") by host All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` ]
```

**Defender KQL:**
```kql
let BadDomains = dynamic(["m-kosche.com","t.m-kosche.com","git-service.com","check.git-service.com"]);
let BadIPs = dynamic(["160.119.64.3","83.142.209.194"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (BadDomains) or RemoteIP in (BadIPs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### [LLM] AWS SSM SendCommand / kubectl exec lateral movement from compromised CI runtime

`UC_8_14` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","python3.14") (Processes.process_name="kubectl" OR Processes.process_name="aws") (Processes.process="*kubectl*exec*" OR Processes.process="*kubectl version --client*" OR Processes.process="*ssm send-command*" OR Processes.process="*ssm start-session*") by host Processes.user Processes.parent_process Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("python","python3","python3.14")
| where (FileName =~ "kubectl" and (ProcessCommandLine has "version --client" or ProcessCommandLine has " exec "))
   or (FileName =~ "aws" and (ProcessCommandLine has "ssm send-command" or ProcessCommandLine has "ssm start-session"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks

`UC_8_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks ```
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
// Article-specific bespoke detection — IronWorm and New Miasma Worm Variant Hit npm in Supply Chain Attacks
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
  - IP / domain IOC(s): `160.119.64.3`, `83.142.209.194`, `check.git-service.com`, `git-service.com`, `t.m-kosche.com`, `m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`, `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
