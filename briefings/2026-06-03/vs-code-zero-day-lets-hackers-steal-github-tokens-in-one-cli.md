# [HIGH] VS Code zero-day lets hackers steal GitHub tokens in one click

**Source:** BleepingComputer
**Published:** 2026-06-03
**Article:** https://www.bleepingcomputer.com/news/security/vs-code-zero-day-lets-hackers-steal-github-tokens-in-one-click/

## Threat Profile

VS Code zero-day lets hackers steal GitHub tokens in one click 
By Sergiu Gatlan 
June 3, 2026
02:50 AM
0 
A security researcher has released exploit code for a Visual Studio Code (VS Code) zero-day vulnerability that allows attackers to steal GitHub authentication tokens by tricking users into clicking a link.
Microsoft classifies a software flaw as a zero-day if it is publicly disclosed and/or actively exploited with no official patch currently available.
As researcher Ammar Askar explained in…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1567** — Exfiltration Over Web Service
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1204.001** — User Execution: Malicious Link
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] VS Code (code.exe) outbound network egress to non-Microsoft/non-GitHub domain

`UC_6_3` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="code.exe" AND All_Traffic.dest_port IN (80,443,8080,8443) by host, All_Traffic.user, All_Traffic.app, All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | where NOT match(dest, "(github\\.com|github\\.dev|githubusercontent\\.com|vscode-cdn\\.net|visualstudio\\.com|microsoft\\.com|azureedge\\.net|vscode-sync\\.trafficmanager\\.net|vscode-unpkg\\.net|openvsxorg\\.blob\\.core\\.windows\\.net|vsmarketplacebadges\\.dev)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TrustedSuffixes = dynamic([".github.com",".github.dev",".githubusercontent.com",".vscode-cdn.net",".visualstudio.com",".microsoft.com",".azureedge.net",".trafficmanager.net",".vscode-unpkg.net",".vsassets.io",".vsmarketplacebadges.dev"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "code.exe"
| where RemoteIPType == "Public"
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected","ConnectionInspected")
| where isnotempty(RemoteUrl)
| where not(RemoteUrl has_any (TrustedSuffixes))
| where not(RemoteUrl endswith "github.com" or RemoteUrl endswith "github.dev")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] VS Code extension file write within 120s of opening a .ipynb notebook (one-click install chain)

`UC_6_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as ipynbTime values(Filesystem.file_path) as notebook_paths from datamodel=Endpoint.Filesystem where Filesystem.process_name="code.exe" AND Filesystem.file_name="*.ipynb" by host, Filesystem.user | `drop_dm_object_name(Filesystem)` | rename user as victim_user | join host victim_user [ | tstats summariesonly=true count min(_time) as extWriteTime values(Filesystem.file_path) as extension_paths from datamodel=Endpoint.Filesystem where Filesystem.process_name="code.exe" AND Filesystem.file_path="*\\.vscode\\extensions\\*" AND (Filesystem.file_name="package.json" OR Filesystem.file_name="extension.js" OR Filesystem.file_name="extension.vsix") by host, Filesystem.user | `drop_dm_object_name(Filesystem)` | rename user as victim_user ] | eval delta_seconds=extWriteTime-ipynbTime | where delta_seconds > 0 AND delta_seconds < 120 | `security_content_ctime(ipynbTime)` | `security_content_ctime(extWriteTime)`
```

**Defender KQL:**
```kql
let WindowSec = 120s;
let Notebooks = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "code.exe"
    | where FileName endswith ".ipynb"
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where InitiatingProcessAccountName !endswith "$"
    | project NotebookTime = Timestamp, DeviceId, DeviceName, AccountName = InitiatingProcessAccountName, NotebookPath = FolderPath, NotebookName = FileName, NotebookSrc = FileOriginUrl;
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "code.exe"
| where FolderPath has @"\.vscode\extensions\"
| where ActionType == "FileCreated"
| where FileName in~ ("package.json","extension.js","extension.vsix")
| where InitiatingProcessAccountName !endswith "$"
| project ExtWriteTime = Timestamp, DeviceId, ExtAccount = InitiatingProcessAccountName, ExtFolderPath = FolderPath, ExtFileName = FileName
| join kind=inner Notebooks on DeviceId
| where ExtAccount =~ AccountName
| where ExtWriteTime between (NotebookTime .. NotebookTime + WindowSec)
| extend DelaySec = datetime_diff('second', ExtWriteTime, NotebookTime)
| project NotebookTime, ExtWriteTime, DelaySec, DeviceName, AccountName, NotebookName, NotebookPath, NotebookSrc, ExtFolderPath, ExtFileName
| order by NotebookTime desc
```

### [LLM] Mass GitHub private repository enumeration in short window (stolen OAuth token reuse)

`UC_6_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*api.github.com/user/repos*" OR Web.url="*api.github.com/repositories*" OR Web.url="*api.github.com/orgs/*/repos*" OR Web.url="*api.github.com/users/*/repos*") AND Web.status<400 by Web.user, Web.src, Web.url, _time | `drop_dm_object_name(Web)` | bin _time span=5m | stats sum(count) as request_count dc(url) as distinct_urls values(url) as urls values(src) as src_ips by user, _time | where request_count > 30 OR distinct_urls > 25 | `security_content_ctime(_time)`
```

**Defender KQL:**
```kql
let WindowMin = 5m;
let RepoThreshold = 25;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "GitHub"
| where ActionType in~ ("RepositoryReadAccess","List user repositories","List organization repositories","Get repository","git.clone","git.fetch","Repository_Cloned")
   or ActivityType in~ ("read_repository","list_repositories","clone_repository")
| where isnotempty(ObjectName)
| summarize RepoCount = dcount(ObjectName), Repos = make_set(ObjectName, 50), SrcIps = make_set(IPAddress, 10), UserAgents = make_set(UserAgent, 10), FirstAccess = min(Timestamp), LastAccess = max(Timestamp)
  by AccountObjectId, AccountDisplayName, AccountId, bin(Timestamp, WindowMin)
| where RepoCount > RepoThreshold
| extend BurstSeconds = datetime_diff('second', LastAccess, FirstAccess)
| where BurstSeconds < 300
| order by RepoCount desc
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
