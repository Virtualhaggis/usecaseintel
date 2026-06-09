# [HIGH] Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack

**Source:** StepSecurity
**Published:** 2026-06-06
**Article:** https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack

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
- **T1078** — Valid Accounts
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1204.003** — User Execution: Malicious Image
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1552.001** — Credentials In Files
- **T1552.005** — Cloud Instance Metadata API
- **T1555** — Credentials from Password Stores
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1021.007** — Cloud Services
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1580** — Cloud Infrastructure Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Pip install of compromised Microsoft durabletask versions 1.4.1-1.4.3

`UC_41_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pip","pip3","pip3.10","pip3.11","pip3.12","pip3.13","pip3.14","python","python3") AND (Processes.process="*durabletask==1.4.1*" OR Processes.process="*durabletask==1.4.2*" OR Processes.process="*durabletask==1.4.3*" OR (Processes.process="*install*" AND Processes.process="*durabletask*" AND Processes.process!="*durabletask==1.4.0*")) by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "durabletask"
| where ProcessCommandLine has "install"
| where InitiatingProcessFileName in~ ("pip","pip3","python","python3") or FileName in~ ("pip","pip3","python","python3")
| where ProcessCommandLine has_any ("durabletask==1.4.1","durabletask==1.4.2","durabletask==1.4.3")
   or (ProcessCommandLine has "durabletask" and ProcessCommandLine !has "durabletask==1.4.0" and ProcessCommandLine !has "durabletask<1.4.1" and Timestamp between (datetime(2026-05-19) .. datetime(2026-05-20T12:00:00Z)))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] rope.pyz dropper executed as /tmp/managed.pyz from durabletask import

`UC_41_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*managed.pyz*" OR (Processes.parent_process="*import durabletask*" AND Processes.process_name="python3") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "/tmp/managed.pyz"
   or InitiatingProcessCommandLine has "/tmp/managed.pyz"
   or (InitiatingProcessCommandLine has "import durabletask" and FileName in~ ("python","python3"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp asc
```

### [LLM] Egress to TeamPCP rope.pyz C2 infrastructure (check.git-service.com / t.m-kosche.com / 160.119.64.3)

`UC_41_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("check.git-service.com","git-service.com","*.git-service.com","t.m-kosche.com","m-kosche.com","*.m-kosche.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`) | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="160.119.64.3" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_domains = dynamic(["check.git-service.com","git-service.com","t.m-kosche.com","m-kosche.com"]);
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl has_any (bad_domains) or RemoteIP == "160.119.64.3"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] gh auth token / gpg-decrypt credential harvesting by python3 child

`UC_41_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmd_samples min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="python3" AND ( (Processes.process_name="gh" AND (Processes.process="*auth token*" OR Processes.process="*auth status --show-token*")) OR (Processes.process_name="gpg" AND Processes.process="*--batch --passphrase anon --decrypt*") ) by Processes.dest Processes.user Processes.process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python","python3")
| where (FileName =~ "gh" and (ProcessCommandLine has "auth token" or ProcessCommandLine has "auth status --show-token"))
   or (FileName =~ "gpg" and ProcessCommandLine has_all ("--batch","--passphrase anon","--decrypt"))
| summarize CommandCount = count(),
            Commands = make_set(ProcessCommandLine),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
         by DeviceName, AccountName, InitiatingProcessId, InitiatingProcessCommandLine
| where CommandCount >= 1
| order by FirstSeen desc
```

### [LLM] Fake pgsql-monitor.service systemd persistence written under ~/.config/systemd/user/

`UC_41_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(`tstats` summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="pgsql-monitor.service" OR (Filesystem.file_path="*/.config/systemd/user/*" AND Filesystem.action="created") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)`) | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="systemctl" AND Processes.process="*--user*daemon-reload*" AND Processes.parent_process_name="python3" by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let file_persist = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where (FolderPath has "/.config/systemd/user" and FileName endswith ".service")
     or FileName =~ "pgsql-monitor.service"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, Signal="FileWrite";
let daemon_reload = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName =~ "systemctl"
  | where ProcessCommandLine has "--user" and ProcessCommandLine has "daemon-reload"
  | where InitiatingProcessFileName in~ ("python","python3")
  | project Timestamp, DeviceName, AccountName, FileName="systemctl", FolderPath=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Signal="DaemonReload";
union file_persist, daemon_reload
| order by Timestamp desc
```

### [LLM] Burst of AWS SSM SendCommand / StartSession from stolen durabletask credentials

`UC_41_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`cloudtrail` (eventName=DescribeInstanceInformation OR eventName=SendCommand OR eventName=StartSession OR eventName=ResumeSession) errorCode="*" OR errorCode=NULL
| eval principal=coalesce('userIdentity.arn','userIdentity.userName')
| stats earliest(_time) as firstSeen latest(_time) as lastSeen dc(eventName) as eventTypes values(eventName) as events values(sourceIPAddress) as srcIPs dc(sourceIPAddress) as srcIPCount count by principal
| where eventTypes >= 2 AND srcIPCount >= 1
| eval windowSec=lastSeen-firstSeen
| where windowSec <= 1800
| convert ctime(firstSeen) ctime(lastSeen)
| sort - firstSeen
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

### Article-specific behavioural hunt — Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack

`UC_41_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack ```
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
// Article-specific bespoke detection — Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack
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
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
