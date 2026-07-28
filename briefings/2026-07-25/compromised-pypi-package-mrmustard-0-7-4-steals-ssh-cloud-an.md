# [CRIT] Compromised PyPI Package: mrmustard 0.7.4 Steals SSH, Cloud, and Kubernetes Credentials

**Source:** StepSecurity
**Published:** 2026-07-25
**Article:** https://www.stepsecurity.io/blog/compromised-pypi-mrmustard-0-7-4-credential-stealer

## Threat Profile

Back to Blog Threat Intel Compromised PyPI Package: mrmustard 0.7.4 Steals SSH, Cloud, and Kubernetes Credentials A hijacked maintainer account published mrmustard 0.7.4 to PyPI with a credential stealer that runs on import, exfiltrating SSH keys, AWS, and Kubernetes credentials from developer and research machines. Full analysis, IOCs, and response steps. Varun Sharma View LinkedIn July 24, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loa…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `metrics.femboy.energy`
- **Domain (defanged):** `femboy.energy`
- **SHA256:** `0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb`
- **SHA256:** `81f0d1291a975d012d1b892cf9967557fdbb1ad4e1ac0545702ad235ace1cac5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1546** — Event Triggered Execution
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1053.003** — Scheduled Task/Job: Cron
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### mrmustard stealer C2 exfil to metrics.femboy.energy

`UC_39_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query="*femboy.energy*" by DNS.src DNS.dest DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "femboy.energy" or RemoteUrl endswith "femboy.energy"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Python interpreter reading SSH + AWS + Kube credential stores

`UC_39_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as distinct_paths values(Filesystem.file_path) as file_paths min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.kube/config") by Filesystem.dest Filesystem.user _time span=5m
| `drop_dm_object_name(Filesystem)`
| eventstats dc(eval(if(match(file_paths,"/\.ssh/"),"ssh",if(match(file_paths,"/\.aws/"),"aws",if(match(file_paths,"/\.kube/"),"kube",null()))))) as store_count by dest
| where distinct_paths >= 2
| convert ctime(firstTime)
| sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has "python"
| extend SecretStore = case(FolderPath has "/.ssh", "ssh", FolderPath has "/.aws", "aws", FolderPath has "/.kube", "kube", "")
| where SecretStore != ""
| summarize StoreCount = dcount(SecretStore), Stores = make_set(SecretStore), Files = make_set(FolderPath, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where StoreCount >= 2   // one python process touching >=2 of {ssh,aws,kube} = harvest pattern
| order by FirstSeen desc
```

### mrmustard persistence artifacts: mmcompat.pth and .tf_cache/hw_probe.pyc

`UC_39_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="mmcompat.pth" OR Filesystem.file_name="hw_probe.pyc" OR Filesystem.file_path="*/.cache/.tf_cache/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName =~ "mmcompat.pth" or FileName =~ "hw_probe.pyc" or FolderPath has "/.cache/.tf_cache/"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Recurring cron/shell-rc execution of .tf_cache/hw_probe.pyc payload

`UC_39_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*hw_probe.pyc*" OR Processes.process="*/.cache/.tf_cache/*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "hw_probe.pyc" or ProcessCommandLine has "/.cache/.tf_cache/"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### Malicious mrmustard 0.7.4 artifact by hash or filename

`UC_39_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb" OR Filesystem.file_hash="81f0d1291a975d012d1b892cf9967557fdbb1ad4e1ac0545702ad235ace1cac5" OR Filesystem.file_name="mrmustard-0.7.4*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where SHA256 in~ ("0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb", "81f0d1291a975d012d1b892cf9967557fdbb1ad4e1ac0545702ad235ace1cac5")
    or FileName startswith "mrmustard-0.7.4"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, SHA256
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

### Article-specific behavioural hunt — Compromised PyPI Package: mrmustard 0.7.4 Steals SSH, Cloud, and Kubernetes Cred

`UC_39_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Compromised PyPI Package: mrmustard 0.7.4 Steals SSH, Cloud, and Kubernetes Cred ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/home/runner/.cache/.tf_cache/hw_probe.pyc*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("__init__.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Compromised PyPI Package: mrmustard 0.7.4 Steals SSH, Cloud, and Kubernetes Cred
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env", "/home/runner/.cache/.tf_cache/hw_probe.pyc", "/dev/null") or FileName in~ ("__init__.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `metrics.femboy.energy`, `femboy.energy`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb`, `81f0d1291a975d012d1b892cf9967557fdbb1ad4e1ac0545702ad235ace1cac5`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
