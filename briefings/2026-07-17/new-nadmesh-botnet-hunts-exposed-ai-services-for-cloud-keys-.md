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
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.007** — Unsecured Credentials: Container API
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1610** — Deploy Container
- **T1046** — Network Service Discovery
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1098** — Account Manipulation
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NadMesh Linux persistence: hidden drop files in /dev/shm, /tmp and stealth cron.d entries

`UC_6_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/dev/shm/.a","/var/tmp/.a","/tmp/.a","/etc/cron.d/.sys_monitor","/etc/cron.d/.s")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "/etc/cron.d/" and FileName in~ (".sys_monitor",".s"))
    or (FileName == ".a" and FolderPath has_any ("/dev/shm/","/var/tmp/","/tmp/"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA1
| order by Timestamp desc
```

### NadMesh C2 callback to 209.99.186.235 / cdnorigin.net or agent SHA1 execution

`UC_6_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="209.99.186.235" by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "209.99.186.235"
    or RemoteUrl has "cdnorigin.net"
    or InitiatingProcessSHA1 == "31c69b3e12936abca770d430066f379ec1d997ec"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA1, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### NadMesh cloud-credential harvesting: reads of ~/.aws, .env, ~/.docker/config.json and cloud env vars

`UC_6_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*.aws/config*" OR Processes.process="*.aws/credentials*" OR Processes.process="*.docker/config.json*" OR Processes.process="*.env*" OR Processes.process="*AWS_SECRET_ACCESS_KEY*" OR Processes.process="*GOOGLE_APPLICATION_CREDENTIALS*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (ProcessCommandLine contains ".aws/" or ProcessCommandLine contains ".docker/config.json" or ProcessCommandLine contains ".env" or ProcessCommandLine contains "AWS_SECRET_ACCESS_KEY" or ProcessCommandLine contains "GOOGLE_APPLICATION_CREDENTIALS")
    or (FileName in~ ("env","printenv") and ProcessCommandLine has_any ("AWS_","GOOGLE_","AZURE_","KUBECONFIG"))
| where FileName in~ ("cat","grep","head","tail","cp","tar","base64","xxd","strings","awk","less","more","curl","env","printenv","sh","bash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Kubernetes ServiceAccount token / kubeconfig access by bot processes and anonymous secret reads

`UC_6_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*/var/run/secrets/kubernetes.io/serviceaccount*" OR Processes.process="*.kube/config*" OR Processes.process="*KUBECONFIG*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("/var/run/secrets/kubernetes.io/serviceaccount", "/.kube/config", "KUBECONFIG")
| where FileName in~ ("cat","grep","curl","wget","base64","tar","cp","head","kubectl","sh","bash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Exposed AI/DevOps service exploited: pre-auth RCE endpoints hit + service spawns shell to fetch NadMesh

`UC_6_10` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("rclone","marimo","python","python3","java","node","dockerd") AND Processes.process_name IN ("sh","bash","dash","curl","wget") AND (Processes.process="*curl*" OR Processes.process="*wget*" OR Processes.process="*/dev/shm*" OR Processes.process="*/tmp/.a*" OR Processes.process="*chmod +x*" OR Processes.process="*base64 -d*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("rclone","marimo","python","python3","java","node","dockerd","gunicorn","uvicorn")
| where FileName in~ ("sh","bash","dash","curl","wget")
| where ProcessCommandLine has_any ("curl","wget","/dev/shm","/tmp/.a","/var/tmp/.a","chmod +x","base64 -d")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Exposed Docker Engine API on 2375 hit from the internet (NadMesh top vector)

`UC_6_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=2375 by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.action | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 2375 or RemotePort == 2375
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess","ConnectionAttempt")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

### Internal host mass-scanning AI service ports 8188/11434/7860/5678 (NadMesh Shodan-style sweep)

`UC_6_12` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.dest_ip) as distinct_targets values(All_Traffic.dest_port) as ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (8188,11434,7860,5678) by All_Traffic.src _time span=15m | `drop_dm_object_name(All_Traffic)` | where distinct_targets > 50
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType in ("ConnectionAttempt","ConnectionSuccess","ConnectionFailed")
| where RemotePort in (8188, 11434, 7860, 5678)
| summarize DistinctTargets = dcount(RemoteIP), Ports = make_set(RemotePort), Attempts = count()
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 15m)
| where DistinctTargets > 50   // one host probing 50+ distinct IPs on AI ports in 15m = sweep, not client use
| order by DistinctTargets desc
```

### Kubernetes privilege escalation via stolen tokens: anonymous/SA creating ClusterRoleBindings

`UC_6_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=kubernetes (sourcetype="kube:apiserver:audit" OR sourcetype="aws:eks:audit") verb IN ("create","update","patch") "objectRef.resource" IN ("clusterrolebindings","clusterroles","rolebindings") ("user.username"="system:anonymous" OR "user.username"="system:serviceaccount:*") | stats count min(_time) as firstTime max(_time) as lastTime values(objectRef.name) as objects values(requestObject.roleRef.name) as boundRole by user.username verb objectRef.resource | `security_content_ctime(firstTime)`
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

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
