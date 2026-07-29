# [HIGH] Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Repositories

**Source:** StepSecurity
**Published:** 2026-05-22
**Article:** https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories

## Threat Profile

Back to Blog Threat Intel Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Repositories A forged commit. A workflow file disguised as a routine CI optimization. Within 6 hours, 5,561 GitHub repositories were backdoored. Cloud credentials harvested. SSH keys stolen. OIDC tokens minted and exfiltrated before any runner finished. The attacker never touched your application code, only your pipeline. Most repositories had no idea it happened. Rohan Prabhu View LinkedIn May 22, …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `216.126.225.129`
- **Domain (defanged):** `github-ci.com`
- **Domain (defanged):** `actions-bot.com`
- **SHA1:** `acac5a9854650c4ae2883c4740bf87d34120c038`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1041** — Exfiltration Over C2 Channel
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1554** — Compromise Host Software Binary
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1555** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Megalodon CI/CD exfil: outbound HTTPS to C2 216.126.225.129:8443

`UC_397_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest_ip="216.126.225.129" OR All_Traffic.dest="216.126.225.129") by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "216.126.225.129"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Megalodon harvester: curl POST to C2 /collect endpoint on Linux runner

`UC_397_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=curl OR Processes.process_name=curl.exe) Processes.process="*216.126.225.129*" Processes.process="*/collect*" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl" or FileName =~ "curl.exe" or FolderPath endswith "/curl"
| where ProcessCommandLine has "216.126.225.129" and ProcessCommandLine has "/collect"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Megalodon harvester: bash secret-grep across workspace (API_KEY|SECRET|TOKEN|PRIVATE_KEY|BEGIN RSA)

`UC_397_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=grep Processes.process="*API_KEY*" Processes.process="*SECRET*" Processes.process="*TOKEN*" Processes.process="*PASSWORD*" Processes.process="*PRIVATE_KEY*" Processes.process="*BEGIN RSA*" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "grep" or FolderPath endswith "/grep"
| where ProcessCommandLine has_all ("API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY", "BEGIN RSA")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Megalodon backdoor workflow file (SysDiag.yml / Optimize-Build.yml) written to .github/workflows/

`UC_397_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*.github/workflows/*" OR Filesystem.file_path="*.github\\workflows\\*") (Filesystem.file_name="SysDiag.yml" OR Filesystem.file_name="Optimize-Build.yml") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has ".github\\workflows" or FolderPath has ".github/workflows"
| where FileName in~ ("SysDiag.yml","Optimize-Build.yml")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Megalodon harvester: clustered read of ~/.ssh/id_*, ~/.kube/config, ~/.npmrc, ~/.docker/config.json in one session

`UC_397_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds from datamodel=Endpoint.Processes where Processes.process_name=cat (Processes.process="*/proc/1/environ*" OR Processes.process="*/.ssh/id_*" OR Processes.process="*/.kube/config*" OR Processes.process="*/.npmrc*" OR Processes.process="*/.docker/config.json*") by Processes.dest Processes.user Processes.parent_process_id Processes.parent_process_name _time span=1m | `drop_dm_object_name(Processes)` | eval is_ssh=if(match(mvjoin(cmds,"|"),"/.ssh/id_"),1,0), is_kube=if(match(mvjoin(cmds,"|"),"/.kube/config"),1,0), is_npm=if(match(mvjoin(cmds,"|"),"/.npmrc"),1,0), is_proc=if(match(mvjoin(cmds,"|"),"/proc/1/environ"),1,0), is_docker=if(match(mvjoin(cmds,"|"),"/.docker/config.json"),1,0) | eval distinct_targets=is_ssh+is_kube+is_npm+is_proc+is_docker | where distinct_targets>=3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 1m;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName =~ "cat" or FolderPath endswith "/cat"
| where ProcessCommandLine has_any ("/proc/1/environ","/.ssh/id_","/.kube/config","/.npmrc","/.docker/config.json")
| extend Target = case(
    ProcessCommandLine has "/proc/1/environ","pid1_env",
    ProcessCommandLine has "/.ssh/id_","ssh_key",
    ProcessCommandLine has "/.kube/config","kube",
    ProcessCommandLine has "/.npmrc","npm",
    ProcessCommandLine has "/.docker/config.json","docker",
    "")
| summarize
    DistinctTargets = dcount(Target),
    Targets = make_set(Target, 10),
    SampleCmds = make_set(ProcessCommandLine, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, AccountName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, WindowMin)
| where DistinctTargets >= 3
| order by LastSeen desc
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

### Article-specific behavioural hunt — Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Reposito

`UC_397_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Reposito ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Megalodon: Mass GitHub Actions Secret Exfiltration Across 5,500+ Public Reposito
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `216.126.225.129`, `github-ci.com`, `actions-bot.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `acac5a9854650c4ae2883c4740bf87d34120c038`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
