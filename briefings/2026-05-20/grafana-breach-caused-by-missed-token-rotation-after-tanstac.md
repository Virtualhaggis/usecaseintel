# [HIGH] Grafana breach caused by missed token rotation after TanStack attack

**Source:** BleepingComputer, Microsoft Security Blog, StepSecurity
**Published:** 2026-05-20
**Article:** https://www.bleepingcomputer.com/news/security/grafana-breach-caused-by-missed-token-rotation-after-tanstack-attack/

## Threat Profile

Back to Blog Threat Intel Microsoft's durabletask PyPI Package Compromised in Supply Chain Attack Three malicious versions of Microsoft's official durabletask Python SDK were published to PyPI on May 19, 2026. The compromised package silently downloads and executes a 28 KB payload that steals credentials from AWS, Azure, GCP, Kubernetes, password managers, and over 90 developer tool configurations, then spreads laterally through cloud infrastructure. The payload skips systems with a Russian loca…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `185.95.159.32`
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
- **T1059.004** — Unix Shell
- **T1546.016** — Installer Packages
- **T1548.003** — Sudo and Sudo Caching
- **T1222.002** — Linux and Mac File and Directory Permissions Modification
- **T1003** — OS Credential Dumping
- **T1057** — Process Discovery
- **T1552.001** — Credentials In Files
- **T1552.005** — Cloud Instance Metadata API
- **T1555** — Credentials from Password Stores
- **T1526** — Cloud Service Discovery
- **T1555.006** — Cloud Secrets Management Stores
- **T1078.004** — Cloud Accounts
- **T1573** — Encrypted Channel
- **T1567.001** — Exfiltration to Code Repository

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious @antv preinstall chain: node spawns sh spawns bun on Linux CI runner

`UC_39_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent_name from datamodel=Endpoint.Processes where Processes.process_name=bun (Processes.parent_process_name=sh OR Processes.parent_process_name=bash OR Processes.parent_process_name=dash) (Processes.process="*.claude/*" OR Processes.process="*preinstall*" OR Processes.process="*node_modules/@antv/*") by Processes.dest Processes.user Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | where match(parent_cmd,"(?i)node|npm|npx|yarn|pnpm") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bun"
| where InitiatingProcessFileName in~ ("sh","bash","dash")
| where InitiatingProcessParentFileName in~ ("node","npm","npx","yarn","pnpm")
| where ProcessCommandLine has_any (".claude/","@antv/","preinstall","echarts-for-react","size-sensor")
   or InitiatingProcessCommandLine has_any (".claude/","@antv/","preinstall")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Trojanised @antv payload SHA256 / 499KB single-line index.js on disk

`UC_39_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.file_hash) as hash values(Filesystem.file_size) as size from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b" OR Filesystem.file_hash="d78c25443ec4a0d7f0a85776461f3b1163132537" OR Filesystem.file_hash="1916faa365f2788b6e193514872d51a242876569" OR (Filesystem.file_name="index.js" AND Filesystem.file_path="*node_modules/@antv/*")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where SHA256 in ("7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b")
   or SHA1 in ("d78c25443ec4a0d7f0a85776461f3b1163132537","1916faa365f2788b6e193514872d51a242876569")
   or (FileName =~ "index.js" and FolderPath has "node_modules/@antv/" and FileSize between (450000 .. 560000))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize, SHA256, SHA1,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Passwordless sudoers rule injected via bind mount at /mnt or /etc/sudoers.d

`UC_39_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as image values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="*NOPASSWD:ALL*" OR Processes.process="*runner ALL=(ALL)*") (Processes.process="*/mnt/runner*" OR Processes.process="*/etc/sudoers.d/*" OR Processes.process="*mount*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "NOPASSWD:ALL"
   or (ProcessCommandLine has_any ("/mnt/runner","/etc/sudoers.d") and ProcessCommandLine has_any ("echo","tee","mount","bind"))
| where InitiatingProcessFileName in~ ("node","bun","sh","bash","dash","npm")
   or InitiatingProcessParentFileName in~ ("node","bun","npm")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] GitHub Actions Runner.Worker process memory scraping via /proc

`UC_39_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_path) as image from datamodel=Endpoint.Processes where (Processes.process="*Runner.Worker*" OR (Processes.process="*/proc/*/mem*") OR (Processes.process="*isSecret*" AND Processes.process="*value*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "Runner.Worker"
   or ProcessCommandLine matches regex @"/proc/\d+/(mem|cmdline)"
   or ProcessCommandLine has_all ("isSecret","value")
   or ProcessCommandLine has "findRunnerWorkerPIDLinux"
| where InitiatingProcessFileName in~ ("node","bun","sh","bash")
   or InitiatingProcessParentFileName in~ ("node","bun","npm")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Cloud / Vault / Kubernetes credential file harvesting from npm or bun lineage

`UC_39_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/var/run/secrets/vault/token" OR Filesystem.file_path="*/var/run/secrets/kubernetes.io/serviceaccount/token" OR Filesystem.file_path="*/etc/vault/token" OR Filesystem.file_path="*/.npmrc") (Filesystem.process_name="node" OR Filesystem.process_name="bun" OR Filesystem.process_name="npm" OR Filesystem.process_name="sh" OR Filesystem.process_name="bash") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let CredFiles = pack_array(
    "/.aws/credentials","/.aws/config","/.vault-token",
    "/var/run/secrets/vault/token","/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/etc/vault/token","/home/runner/.vault-token","/root/.vault-token",
    "/.npmrc","/.config/op/config"
);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileAccessed","FileCreated","FileModified","FileRead")
| where FolderPath has_any (CredFiles) or strcat(FolderPath, FileName) has_any (CredFiles)
| where InitiatingProcessFileName in~ ("node","bun","npm","sh","bash","dash")
   or InitiatingProcessParentFileName in~ ("node","bun","npm")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] AWS SecretsManager region-wide enumeration burst from CI identity

`UC_39_13` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`cloudtrail` (eventName=ListSecrets OR eventName=GetSecretValue) eventSource=secretsmanager.amazonaws.com
| stats min(_time) as firstTime max(_time) as lastTime dc(awsRegion) as regions dc(eventName) as apis count by userIdentity.arn userIdentity.type sourceIPAddress
| where regions >= 5
| eval duration=lastTime-firstTime
| where duration < 600
| `security_content_ctime(firstTime)`
```

### [LLM] DNS or HTTPS to Shai-Hulud C2 (t.m-kosche.com, check.git-service.com)

`UC_39_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`cim_Network_Resolution_indexes` (query="t.m-kosche.com" OR query="check.git-service.com" OR query="*.m-kosche.com" OR query="*.git-service.com")
| stats min(_time) as firstTime max(_time) as lastTime dc(src) as hosts count by query src
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
(
  DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any ("t.m-kosche.com","m-kosche.com","check.git-service.com","git-service.com")
  | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessAccountName, ActionType
),
(
  DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse" or ActionType has "Dns"
  | where RemoteUrl has_any ("t.m-kosche.com","m-kosche.com","check.git-service.com","git-service.com")
      or AdditionalFields has_any ("t.m-kosche.com","check.git-service.com")
  | project Timestamp, DeviceName, RemoteUrl, ActionType, AdditionalFields,
            InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### [LLM] GitHub repo creation with 'Shai-Hulud :We Here Go Again' reversed description

`UC_39_15` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`github_audit` (action="repo.create" OR action="repo.publicize")
| search (description="*Shai-Hulud*" OR description="*duluH-iahS*" OR description="*niagA oG eW ereH*" OR description="*We Here Go Again*")
| stats min(_time) as firstTime max(_time) as lastTime values(repo) as repos count by actor description
| `security_content_ctime(firstTime)`
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

### Article-specific behavioural hunt — Grafana breach caused by missed token rotation after TanStack attack

`UC_39_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Grafana breach caused by missed token rotation after TanStack attack ```
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
// Article-specific bespoke detection — Grafana breach caused by missed token rotation after TanStack attack
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
  - IP / domain IOC(s): `160.119.64.3`, `185.95.159.32`, `83.142.209.194`, `check.git-service.com`, `git-service.com`, `t.m-kosche.com`, `m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`, `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 16 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
