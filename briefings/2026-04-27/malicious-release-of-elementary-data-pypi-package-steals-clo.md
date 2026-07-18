# [HIGH] Malicious Release of elementary-data PyPI Package Steals Cloud Credentials from Data Engineers

**Source:** Snyk
**Published:** 2026-04-27
**Article:** https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
April 27, 2026
0 mins read A Python package on PyPI called elementary-data , with over 1 million downloads per month, has suffered a supply chain security attack sourced through a GitHub Actions attack vector.
TL;DR Advisory 
SNYK-PYTHON-ELEMENTARYDATA-16316110 
Severity 
Critical (CVSS v4.0: 9.3)
Affected package 
elementary-data==0.23.3 
Clean versions 
All versions except 0.23.3 ; upgrade to 0.23.4 
Attack type 
Supply chain (GitHub Actions CI/C…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud`
- **SHA256:** `31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255`
- **SHA1:** `b1e4b1f3aad0d489ab0e9208031c67402bbb8480`

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
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1070.004** — Indicator Removal: File Deletion
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised elementary-data==0.23.3 PyPI install on developer / CI host

`UC_438_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","python.exe","python","python3","uv.exe","uv","pipx","pipx.exe") OR Processes.process="*pip install*" OR Processes.process="*pip3 install*" OR Processes.process="*uv pip install*" OR Processes.process="*pipx install*") Processes.process="*elementary-data*" Processes.process="*0.23.3*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "elementary-data"
| where ProcessCommandLine has "0.23.3"
| where ProcessCommandLine has_any ("pip install", "pip3 install", "pip download", "uv pip", "pipx install", "poetry add", "poetry install")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Trinny marker file creation (.trinny-security-update)

`UC_438_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name=".trinny-security-update" by Filesystem.dest Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ ".trinny-security-update"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Credential archive staging — trin.tar.gz created by python process

`UC_438_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name="trin.tar.gz" by Filesystem.dest Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "trin.tar.gz"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Exfil to skyhanni.cloud C2 with X-Rise-To-The-Trinny header

`UC_438_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*skyhanni.cloud" OR All_Traffic.dest_host="*skyhanni.cloud" OR All_Traffic.url="*skyhanni.cloud*" OR All_Traffic.dest_host="igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud") by All_Traffic.dest_host All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process="*X-Rise-To-The-Trinny*" OR (Processes.process_name IN ("curl.exe","curl","wget.exe","wget") AND Processes.process="*trin.tar.gz*" AND Processes.process="*--data-binary*")) by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Egress = DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "skyhanni.cloud" or RemoteUrl has "igotnofriendsonlineorirl-imgonnakmslmao"
  | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
let Curl = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has_any ("X-Rise-To-The-Trinny", "igotnofriendsonlineorirl-imgonnakmslmao", "skyhanni.cloud")
     or (FileName in~ ("curl.exe","curl","wget.exe","wget") and ProcessCommandLine has "trin.tar.gz" and ProcessCommandLine has "--data-binary")
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
union Egress, Curl
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

### Article-specific behavioural hunt — Malicious Release of elementary-data PyPI Package Steals Cloud Credentials from

`UC_438_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious Release of elementary-data PyPI Package Steals Cloud Credentials from ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("site.py","__init__.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/kubernetes/*" OR Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_path="*/var/log/auth.log*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("site.py","__init__.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious Release of elementary-data PyPI Package Steals Cloud Credentials from
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("site.py", "__init__.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/kubernetes/", "/etc/passwd", "/etc/shadow", "/var/log/auth.log", "/dev/null") or FileName in~ ("site.py", "__init__.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `31ecc5939de6d24cf60c50d4ca26cf7a8c322db82a8ce4bd122ebd89cf634255`, `b1e4b1f3aad0d489ab0e9208031c67402bbb8480`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
