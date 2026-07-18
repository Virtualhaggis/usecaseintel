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
- **T1053.003** — Scheduled Task/Job: Cron
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1610** — Deploy Container
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.007** — Unsecured Credentials: Container API / SA Token
- **T1046** — Network Service Discovery
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1595.002** — Active Scanning: Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NadMesh Linux persistence: hidden dotfile drops, cron files, authorized_keys tamper

`UC_6_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/dev/shm/.a","/var/tmp/.a","/tmp/.a","/etc/cron.d/.sys_monitor","/etc/cron.d/.s") OR Filesystem.file_path="*/.ssh/authorized_keys") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath in~ ("/dev/shm/.a","/var/tmp/.a","/tmp/.a","/etc/cron.d/.sys_monitor","/etc/cron.d/.s")
     or FolderPath endswith "/.ssh/authorized_keys"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessSHA1
| order by Timestamp desc
```

### NadMesh C2 beacon to 209.99.186.235 / cdnorigin.net or known agent SHA1

`UC_6_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="209.99.186.235" by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS where DNS.query="cdnorigin.net" OR DNS.query="*.cdnorigin.net" by DNS.src DNS.query | `drop_dm_object_name(DNS)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "209.99.186.235" or RemoteUrl has "cdnorigin.net"
| project Timestamp, DeviceName, Indicator = strcat(RemoteIP, " ", RemoteUrl), RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA1),
(DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 == "31c69b3e12936abca770d430066f379ec1d997ec"
| project Timestamp, DeviceName, Indicator = FileName, RemotePort = int(null), InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA1 = SHA1)
| order by Timestamp desc
```

### Exposed Docker Engine API on port 2375 contacted from the public internet

`UC_6_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=2375 (All_Traffic.direction="inbound" OR All_Traffic.src_category="external" OR NOT All_Traffic.src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 2375
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess","ConnectionAttempt")
| where RemoteIPType == "Public"
| summarize Attempts = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, RemoteIP, LocalPort
| order by LastSeen desc
```

### AI/notebook service process spawning shell to fetch NadMesh dropper

`UC_6_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python3","node","java","uvicorn","gunicorn","ollama","containerd-shim","runc") Processes.process_name IN ("sh","bash","dash","curl","wget") (Processes.process="*/tmp/.*" OR Processes.process="*/dev/shm/.*" OR Processes.process="*/var/tmp/.*" OR Processes.process="*chmod +x*" OR Processes.process="*curl *" OR Processes.process="*wget *") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python","python3","node","java","uvicorn","gunicorn","ollama")
| where FileName in~ ("sh","bash","dash","curl","wget")
| where ProcessCommandLine has_any ("/tmp/.","/dev/shm/.","/var/tmp/.","chmod +x","curl ","wget ")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName, SHA1
| order by Timestamp desc
```

### Cloud/K8s credential file harvest by process running from world-writable temp dir

`UC_6_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/var/run/secrets/kubernetes.io/serviceaccount/*" OR Filesystem.file_name=".env") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/.aws/config","/.aws/credentials","/.docker/config.json","/.kube/config","/var/run/secrets/kubernetes.io/serviceaccount") or FileName =~ ".env"
| where InitiatingProcessFolderPath has_any ("/tmp/","/dev/shm/","/var/tmp/")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA1, InitiatingProcessAccountName
| order by Timestamp desc
```

### Scanning fan-out across NadMesh's prioritized AI service ports

`UC_6_11` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Traffic.dest_port) as port_count dc(All_Traffic.dest) as host_count values(All_Traffic.dest_port) as ports min(_time) as firstTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (8188,11434,7860,5678,2375,6379) by All_Traffic.src_ip | `drop_dm_object_name(All_Traffic)` | where port_count>=3 OR host_count>=5 | convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType in ("InboundConnectionAccepted","ConnectionAttempt","ConnectionSuccess")
| where LocalPort in (8188, 11434, 7860, 5678, 2375, 6379)
| where RemoteIPType == "Public"
| summarize DistinctPorts = dcount(LocalPort), DistinctHosts = dcount(DeviceName), Ports = make_set(LocalPort), FirstSeen = min(Timestamp) by RemoteIP
| where DistinctPorts >= 3 or DistinctHosts >= 5   // >=3 of the AI ports, or spraying >=5 hosts
| order by DistinctHosts desc
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

`UC_6_5` · phase: **install** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
