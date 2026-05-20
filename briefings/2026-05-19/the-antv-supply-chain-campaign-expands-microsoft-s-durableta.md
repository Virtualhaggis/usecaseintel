# [HIGH] The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package Compromised

**Source:** Snyk, StepSecurity
**Published:** 2026-05-19
**Article:** https://snyk.io/blog/durabletask-pypi-supply-chain-attack/

## Threat Profile

Back to Blog Product Dev Machine Guard Now Supports Linux Dev Machine Guard now supports Linux, giving security teams full visibility into Linux, macOS, and Windows developer machines. Detect AI coding agents, IDE extensions, MCP servers, npm and system packages, and compromised dependencies across your entire developer fleet from one dashboard. Swarit Pandey View LinkedIn April 29, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav.…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `83.142.209.194`
- **Domain (defanged):** `check.git-service.com`
- **Domain (defanged):** `t.m-kosche.com`
- **SHA256:** `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`
- **SHA256:** `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`
- **SHA256:** `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`
- **SHA256:** `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`
- **SHA256:** `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`
- **SHA256:** `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`
- **SHA256:** `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
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

### [LLM] Compromised Microsoft durabletask PyPI Package Install (TeamPCP 1.4.1-1.4.3)

`UC_14_7` · phase: **delivery** · confidence: **High**

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

### [LLM] TeamPCP rope.pyz Dropper Fetch from check.git-service.com C2

`UC_14_8` · phase: **c2** · confidence: **High**

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

### [LLM] TeamPCP rope.pyz Dropper Infection Markers on Linux

`UC_14_9` · phase: **install** · confidence: **High**

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

### [LLM] AWS SSM SendCommand Fan-out from EC2 Instance Role (TeamPCP Worm Propagation)

`UC_14_10` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`cloudtrail` eventName=SendCommand eventSource="ssm.amazonaws.com" "userIdentity.type"="AssumedRole" 
| eval source_role=mvindex(split('userIdentity.sessionContext.sessionIssuer.arn',"/"),-1)
| eval target_count=mvcount('requestParameters.instanceIds{}')
| stats latest(_time) as last_seen dc('requestParameters.instanceIds{}') as DistinctTargets values('requestParameters.instanceIds{}') as Targets values(sourceIPAddress) as SourceIPs values(userAgent) as UAs by source_role 'userIdentity.arn' awsRegion
| where DistinctTargets >= 3 OR like(source_role, "%ec2%") OR like(source_role, "%-instance-%")
| sort 0 -last_seen
```

### [LLM] Python Process Reading Multi-Cloud Credential Stores (durabletask Stealer Stage)

`UC_14_11` · phase: **actions** · confidence: **Medium**

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

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

`UC_14_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package C ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/share/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package C
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/share/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `160.119.64.3`, `83.142.209.194`, `check.git-service.com`, `t.m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
