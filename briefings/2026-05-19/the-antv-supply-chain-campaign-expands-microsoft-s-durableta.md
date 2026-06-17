# [CRIT] The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package Compromised

**Source:** Snyk, GitHub Security Advisories
**Published:** 2026-05-19
**Article:** https://snyk.io/blog/durabletask-pypi-supply-chain-attack/

## Threat Profile

Malicious code in @beproduct/nestjs-auth (0.1.2 through 0.1.19) — Mini Shai-Hulud worm

## Summary

Between 2026-05-11 20:19 UTC and 22:56 UTC, an attacker used a compromised npm publish token to publish 18 malicious versions of `@beproduct/nestjs-auth` (0.1.2 through 0.1.19). The packages contained payloads from the **Mini Shai-Hulud** npm supply-chain worm campaign described by [Aikido Security](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised).

npm Security removed th…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-46412`
- **Domain (defanged):** `filev2.getsession.org`
- **SHA256:** `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- **SHA256:** `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- **SHA1:** `12ed9a3c1f73617aefdb740480695c04405d7b4b`
- **SHA1:** `e7d582b98ca80690883175470e96f703ef6dc497`
- **MD5:** `833fd59ebe66a4449982c6d18db656b4`
- **MD5:** `b82e54923f7e440664d2d75bd31588ca`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.007** — Remote Services: Cloud Services
- **T1651** — Cloud Administration Command
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1552.001** — Unsecured Credentials: Credentials in Files
- **T1555.005** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised Microsoft durabletask PyPI Package Install (TeamPCP 1.4.1-1.4.3)

`UC_273_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("pip","pip3","python","python3","python3.10","python3.11","python3.12") AND (Processes.process="*durabletask*1.4.1*" OR Processes.process="*durabletask*1.4.2*" OR Processes.process="*durabletask*1.4.3*" OR Processes.process="*durabletask==1.4.*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name _time | `drop_dm_object_name(Processes)` | sort 0 -_time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("pip","pip3","python","python3","python3.10","python3.11","python3.12")
    or InitiatingProcessFileName in~ ("pip","pip3","python","python3")
| where ProcessCommandLine has "durabletask" or InitiatingProcessCommandLine has "durabletask"
| where ProcessCommandLine has_any ("1.4.1","1.4.2","1.4.3","==1.4.")
    or InitiatingProcessCommandLine has_any ("1.4.1","1.4.2","1.4.3","==1.4.")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### TeamPCP rope.pyz Dropper Fetch from check.git-service.com C2

`UC_273_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Resolution.DNS where (DNS.query="check.git-service.com" OR DNS.query="*.git-service.com" OR DNS.query="t.m-kosche.com") by DNS.src DNS.query DNS.answer _time | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*rope.pyz*" OR Web.url="*check.git-service.com*" OR Web.dest_ip IN ("160.119.64.3","83.142.209.194")) by Web.src Web.dest Web.url Web.user_agent _time | `drop_dm_object_name(Web)`] | sort 0 -_time
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where RemoteUrl has_any ("check.git-service.com","t.m-kosche.com","rope.pyz")
      or RemoteIP in ("160.119.64.3","83.142.209.194")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Evt="NetworkConnect"
),
( DeviceEvents
  | where Timestamp > ago(7d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has_any ("check.git-service.com","t.m-kosche.com","git-service.com")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine, RemoteIP="", RemoteUrl=tostring(AdditionalFields), RemotePort=int(null), Evt="DnsQuery"
)
| order by Timestamp desc
```

### TeamPCP rope.pyz Dropper Infection Markers on Linux

`UC_273_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/tmp/rope-*.pyz" OR Filesystem.file_path="/tmp/managed.pyz" OR Filesystem.file_path="*/.cache/.sys-update-check" OR Filesystem.file_path="*/.cache/.sys-update-check-k8s" OR Filesystem.file_name="rope.pyz" OR Filesystem.file_name="managed.pyz" OR Filesystem.file_name=".sys-update-check" OR Filesystem.file_name=".sys-update-check-k8s") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name Filesystem.file_hash _time | `drop_dm_object_name(Filesystem)` | sort 0 -_time
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "/tmp/" and (FileName matches regex @"^rope-.+\.pyz$" or FileName =~ "rope.pyz" or FileName =~ "managed.pyz"))
    or (FolderPath has "/.cache/" and FileName in~ (".sys-update-check",".sys-update-check-k8s"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256, FileSize
| order by Timestamp desc
```

### AWS SSM SendCommand Fan-out from EC2 Instance Role (TeamPCP Worm Propagation)

`UC_273_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`cloudtrail` eventName=SendCommand eventSource="ssm.amazonaws.com" "userIdentity.type"="AssumedRole" 
| eval source_role=mvindex(split('userIdentity.sessionContext.sessionIssuer.arn',"/"),-1)
| eval target_count=mvcount('requestParameters.instanceIds{}')
| stats latest(_time) as last_seen dc('requestParameters.instanceIds{}') as DistinctTargets values('requestParameters.instanceIds{}') as Targets values(sourceIPAddress) as SourceIPs values(userAgent) as UAs by source_role 'userIdentity.arn' awsRegion
| where DistinctTargets >= 3 OR like(source_role, "%ec2%") OR like(source_role, "%-instance-%")
| sort 0 -last_seen
```

### Python Process Reading Multi-Cloud Credential Stores (durabletask Stealer Stage)

`UC_273_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("python","python3","python3.10","python3.11","python3.12") AND (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.azure/accessTokens.json" OR Filesystem.file_path="*/.azure/azureProfile.json" OR Filesystem.file_path="*/.config/gcloud/credentials.db" OR Filesystem.file_path="*/.config/gcloud/application_default_credentials.json" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.git-credentials" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*/.ssh/id_*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id Filesystem.file_path _time | `drop_dm_object_name(Filesystem)` | bin _time span=5m | stats dc(file_path) as DistinctSecretFamilies values(file_path) as Paths min(_time) as first by dest user process_id _time | where DistinctSecretFamilies >= 3 | sort 0 -first
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened","FileCreated","FileRenamed")
| where InitiatingProcessFileName in~ ("python","python3","python3.10","python3.11","python3.12")
| extend SecretFamily = case(
    FolderPath has "/.aws/","aws",
    FolderPath has "/.azure/","azure",
    FolderPath has "/.config/gcloud/","gcp",
    FolderPath has "/.kube/","k8s",
    FolderPath has "/.docker/","docker",
    FileName =~ ".npmrc","npm",
    FileName =~ ".git-credentials","git",
    FolderPath has "/.config/gh/" and FileName =~ "hosts.yml","gh",
    FolderPath has "/.ssh/" and FileName startswith "id_","ssh",
    "other")
| where SecretFamily != "other"
| summarize DistinctSecretFamilies = dcount(SecretFamily), SecretFamilies = make_set(SecretFamily), PathSample = make_set(strcat(FolderPath,"/",FileName), 20), Cmd = any(InitiatingProcessCommandLine), arg_min(Timestamp, *) by DeviceName, InitiatingProcessAccountName, InitiatingProcessId, bin(Timestamp, 5m)
| where DistinctSecretFamilies >= 3
| where InitiatingProcessAccountName !endswith "$"
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

### Article-specific behavioural hunt — The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package C

`UC_273_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package C ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("tanstack_runner.js","router_init.js","router_runtime.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("tanstack_runner.js","router_init.js","router_runtime.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package C
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("tanstack_runner.js", "router_init.js", "router_runtime.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("tanstack_runner.js", "router_init.js", "router_runtime.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-46412`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `filev2.getsession.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`, `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`, `12ed9a3c1f73617aefdb740480695c04405d7b4b`, `e7d582b98ca80690883175470e96f703ef6dc497`, `833fd59ebe66a4449982c6d18db656b4`, `b82e54923f7e440664d2d75bd31588ca`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
