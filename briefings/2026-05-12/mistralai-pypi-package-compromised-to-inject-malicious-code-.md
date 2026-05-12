# [HIGH] MistralAI PyPI Package Compromised to Inject Malicious Code – Microsoft Warns

**Source:** Cyber Security News
**Published:** 2026-05-12
**Article:** https://cybersecuritynews.com/mistralai-pypi-package-compromised/

## Threat Profile

Home Cyber Security News 
MistralAI PyPI Package Compromised to Inject Malicious Code – Microsoft Warns 
By Tushar Subhra Dutta 
May 12, 2026 
A popular AI development library has been turned into a weapon. The mistralai PyPI package, version 2.4.6, was found to contain malicious code secretly injected by attackers, putting developers and organizations worldwide at serious risk. The compromise affects anyone who installed or updated the package, which is widely used for building applications pow…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `pgmonitor.py`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1543.003** — Windows Service
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] MistralAI 2.4.6 Backdoor: Egress to Hardcoded C2 IP 83.142.209.194

`UC_3_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.dest_port) as dest_port values(All_Traffic.user) as user from datamodel=Network_Traffic where All_Traffic.dest_ip="83.142.209.194" by All_Traffic.src All_Traffic.dest All_Traffic.action | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval signature="mistralai_2.4.6_c2_egress"
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.194"
   or (RemoteUrl has "83.142.209.194" and RemoteUrl has "transformers.pyz")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by Timestamp desc
```

### [LLM] MistralAI Backdoor: transformers.pyz Dropped to /tmp on Linux

`UC_3_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user values(Filesystem.action) as action from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/tmp/transformers.pyz" OR (Filesystem.file_name="transformers.pyz" AND Filesystem.file_path="/tmp/*")) by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval signature="mistralai_transformers_pyz_drop"
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath startswith "/tmp/" and FileName =~ "transformers.pyz"
| project Timestamp, DeviceName, DeviceId, FolderPath, FileName, SHA256, MD5,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] MistralAI Backdoor: pgsql-monitor.service / pgmonitor.py Systemd Persistence

`UC_3_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name="pgsql-monitor.service" OR Filesystem.file_name="pgmonitor.py" OR Filesystem.file_path="/etc/systemd/system/pgsql-monitor.service" OR Filesystem.file_path="/etc/systemd/user/pgsql-monitor.service" OR Filesystem.file_path="*/.config/systemd/user/pgsql-monitor.service") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval signature="mistralai_pgsql_monitor_persistence" | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="systemctl" AND (Processes.process="*pgsql-monitor*" OR Processes.process="*pgmonitor*") by Processes.dest Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | eval signature="mistralai_pgsql_monitor_systemctl" ]
```

**Defender KQL:**
```kql
let _files =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where FileName in~ ("pgsql-monitor.service","pgmonitor.py")
       or FolderPath has "/etc/systemd/system/pgsql-monitor"
       or FolderPath has "/etc/systemd/user/pgsql-monitor"
       or FolderPath has "/.config/systemd/user/pgsql-monitor"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              FolderPath, FileName,
              InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256,
              Signal="file_drop";
let _procs =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "systemctl"
       and ProcessCommandLine has_any ("pgsql-monitor","pgmonitor")
    | project Timestamp, DeviceName, AccountName,
              FolderPath, FileName,
              InitiatingProcessFileName=InitiatingProcessFileName,
              InitiatingProcessCommandLine=ProcessCommandLine, SHA256,
              Signal="systemctl_invocation";
union _files, _procs
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

### Service install for persistence — sc.exe / new service registry write

`UC_SERVICE_PERSIST` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\Users\*" OR Processes.process="*\AppData\*"
        OR Processes.process="*\ProgramData\*" OR Processes.process="*\Temp\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\Users\*"
            OR Registry.registry_value_data="*\AppData\*"
            OR Registry.registry_value_data="*\Temp\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\Users\|\AppData\|\ProgramData\|\Temp\)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — MistralAI PyPI Package Compromised to Inject Malicious Code – Microsoft Warns

`UC_3_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — MistralAI PyPI Package Compromised to Inject Malicious Code – Microsoft Warns ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("pgmonitor.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/transformers.pyz*" OR Filesystem.file_name IN ("pgmonitor.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — MistralAI PyPI Package Compromised to Inject Malicious Code – Microsoft Warns
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("pgmonitor.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/transformers.pyz") or FileName in~ ("pgmonitor.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.194`, `pgmonitor.py`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
