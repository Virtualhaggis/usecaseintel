# [HIGH] Mini Shai Hulud: Compromised @antv npm packages enable CI/CD credential theft

**Source:** Microsoft Security Blog, StepSecurity
**Published:** 2026-05-20
**Article:** https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/

## Threat Profile

Back to Blog Threat Intel Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack Three malicious versions of Microsoft's official durabletask Python SDK were published to PyPI on May 19, 2026. The compromised package silently downloads and executes a 28 KB payload that steals credentials from AWS, Azure, GCP, Kubernetes, password managers, and over 90 developer tool configurations, then spreads laterally through cloud infrastructure. The payload skips systems with a Russian loca…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `git-service.com`
- **Domain (defanged):** `t.m-kosche.com`
- **SHA256:** `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`
- **SHA256:** `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`
- **SHA256:** `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142`

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
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution
- **T1106** — Native API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mini Shai-Hulud durabletask dropper C2 callback to git-service.com

`UC_64_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="160.119.64.3" OR All_Traffic.dest_host IN ("check.git-service.com","git-service.com","t.m-kosche.com") OR All_Traffic.url="*check.git-service.com/rope.pyz*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("check.git-service.com","git-service.com","t.m-kosche.com") or RemoteIP == "160.119.64.3"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] durabletask second-stage dropper: python3 executing /tmp/managed.pyz

`UC_64_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_id) as pids from datamodel=Endpoint.Processes where Processes.process_name IN ("python","python3","python3.14") Processes.process="*/tmp/managed.pyz*" by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has "python"
| where ProcessCommandLine has "/tmp/managed.pyz"
| project Timestamp, DeviceName, AccountName, ProcessId, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] gh CLI token enumeration via python parent (managed.pyz credential exfil)

`UC_64_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="gh" (Processes.process="*auth token*" OR Processes.process="*auth status --show-token*") (Processes.parent_process_name IN ("python","python3","python3.14") OR Processes.parent_process="*/tmp/managed.pyz*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "gh"
| where ProcessCommandLine has_any ("auth token","auth status --show-token")
| where InitiatingProcessFileName has "python" or InitiatingProcessCommandLine has "/tmp/managed.pyz" or InitiatingProcessParentFileName has "python"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Fake pgsql-monitor.service systemd user persistence

`UC_64_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*.config/systemd/user*" OR Filesystem.file_path="*/etc/systemd/system*" OR Filesystem.file_path="*/usr/lib/systemd/*") Filesystem.file_name="*pgsql-monitor*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*systemctl --user daemon-reload*" Processes.parent_process_name IN ("python","python3","python3.14") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union isfuzzy=true
(DeviceFileEvents
  | where Timestamp > ago(7d)
  | where FolderPath has_any (".config/systemd/user","/etc/systemd/system","/usr/lib/systemd")
  | where FileName has "pgsql-monitor"
  | project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where ProcessCommandLine has "systemctl" and ProcessCommandLine has "--user" and ProcessCommandLine has "daemon-reload"
  | where InitiatingProcessFileName has "python" or InitiatingProcessCommandLine has "/tmp/managed.pyz"
  | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName)
| order by Timestamp desc
```

### [LLM] Single python parent fans out 3+ managed.pyz children within seconds

`UC_64_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_id) as child_pids from datamodel=Endpoint.Processes where Processes.process="*/tmp/managed.pyz*" by Processes.dest Processes.parent_process_id Processes.parent_process_name Processes.parent_process Processes.user
| `drop_dm_object_name(Processes)`
| where count >= 3
| eval spawn_window_sec = lastTime - firstTime
| where spawn_window_sec <= 60
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "/tmp/managed.pyz"
| summarize ChildCount = count(),
            FirstChild = min(Timestamp),
            LastChild = max(Timestamp),
            ChildPIDs = make_set(ProcessId, 10),
            SampleCmd = any(ProcessCommandLine)
            by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCommandLine, AccountName
| extend SpawnWindowSec = datetime_diff('second', LastChild, FirstChild)
| where ChildCount >= 3 and SpawnWindowSec <= 60
| order by FirstChild desc
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

### Article-specific behavioural hunt — Mini Shai Hulud: Compromised @antv npm packages enable CI/CD credential theft

`UC_64_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mini Shai Hulud: Compromised @antv npm packages enable CI/CD credential theft ```
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
// Article-specific bespoke detection — Mini Shai Hulud: Compromised @antv npm packages enable CI/CD credential theft
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
  - IP / domain IOC(s): `160.119.64.3`, `check.git-service.com`, `git-service.com`, `t.m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`, `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
