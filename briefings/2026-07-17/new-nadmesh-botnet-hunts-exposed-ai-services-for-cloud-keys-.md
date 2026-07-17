# [CRIT] New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Tokens

**Source:** The Hacker News
**Published:** 2026-07-17
**Article:** https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html

## Threat Profile

New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Tokens 
 Swati Khandelwal  Jul 17, 2026 Botnet / AI Security 
A Go botnet called NadMesh turned up in early July hunting exposed AI services, and the operator's own dashboard claims 3,811 unique AWS keys.
A Shodan harvester keeps the scan queue stocked with ComfyUI, Ollama , n8n , Open WebUI , Langflow , and Gradio: the image generators, local model runners, and workflow builders that teams stand up fast and firewall la…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-39987`
- **CVE:** `CVE-2026-41176`
- **CVE:** `CVE-2022-22947`
- **CVE:** `CVE-2017-12611`
- **IPv4 (defanged):** `209.99.186.235`
- **Domain (defanged):** `cdnorigin.net`
- **SHA1:** `31c69b3e12936abca770d430066f379ec1d997ec`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1053.003** — Scheduled Task/Job: Cron
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NadMesh: exposed AI/dev service spawns shell to fetch dropper (ComfyUI/Ollama/n8n/Jenkins/Marimo/rclone)

`UC_5_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python3","ollama","node","java","dockerd","redis-server","rclone","uvicorn","gunicorn","marimo","n8n")) (Processes.process_name IN ("sh","bash","dash","curl","wget")) (Processes.process IN ("*209.99.186.235*","*cdnorigin.net*","*/tmp/.a*","*/var/tmp/.a*","*/dev/shm/.a*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python","python3","ollama","node","java","dockerd","redis-server","rclone","uvicorn","gunicorn","marimo","n8n")
| where FileName in~ ("sh","bash","dash","curl","wget")
| where ProcessCommandLine has_any ("209.99.186.235","cdnorigin.net","/tmp/.a","/var/tmp/.a","/dev/shm/.a")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### NadMesh cloud credential + Kubernetes token harvest (~/.aws/config, .env, ~/.docker/config.json, SA token)

`UC_5_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as processes min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process IN ("*.aws/config*","*.aws/credentials*","*.docker/config.json*","*serviceaccount/token*","*/.env*")) (Processes.parent_process_path IN ("/tmp/*","/var/tmp/*","/dev/shm/*") OR Processes.process_name IN ("cat","grep","head","tar","base64","env","printenv")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (".aws/config",".aws/credentials",".docker/config.json","serviceaccount/token","/.env")
| where FileName in~ ("cat","grep","head","tail","cp","tar","base64","env","printenv","sh","bash")
| where AccountName !endswith "$"
| where InitiatingProcessFolderPath has_any ("/tmp/","/var/tmp/","/dev/shm/") or InitiatingProcessFileName startswith "."
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
```

### NadMesh triple-persistence: hidden agent drops, cron.d beacons and SSH authorized_keys tamper

`UC_5_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/dev/shm/.a","/var/tmp/.a","/tmp/.a","/etc/cron.d/.sys_monitor","/etc/cron.d/.s") OR Filesystem.file_path="*/.ssh/authorized_keys") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/dev/shm/.a","/var/tmp/.a","/tmp/.a","/etc/cron.d/.sys_monitor","/etc/cron.d/.s") or FolderPath endswith "/.ssh/authorized_keys"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### NadMesh C2 contact (209.99.186.235 / cdnorigin.net) and stolen-key use from that IP in CloudTrail

`UC_5_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="209.99.186.235") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "209.99.186.235" or RemoteUrl has "cdnorigin.net" or InitiatingProcessSHA1 == "31c69b3e12936abca770d430066f379ec1d997ec"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessSHA1
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

### Article-specific behavioural hunt — New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Token

`UC_5_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Token ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/shm/.a*" OR Filesystem.file_path="*/var/tmp/.a*" OR Filesystem.file_path="*/tmp/.a*" OR Filesystem.file_path="*/etc/cron.d/.sys_monitor*" OR Filesystem.file_path="*/etc/cron.d/.s*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Token
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/shm/.a", "/var/tmp/.a", "/tmp/.a", "/etc/cron.d/.sys_monitor", "/etc/cron.d/.s"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `209.99.186.235`, `cdnorigin.net`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-39987`, `CVE-2026-41176`, `CVE-2022-22947`, `CVE-2017-12611`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `31c69b3e12936abca770d430066f379ec1d997ec`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
