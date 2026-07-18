# [HIGH] Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Packages Compromised

**Source:** StepSecurity
**Published:** 2025-12-15
**Article:** https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised

## Threat Profile

Back to Blog Threat Intel Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Packages Compromised The Shai-Hulud NPM Worm Returns as "Sha1-Hulud: The Second Coming" - Devastating Supply Chain Attack Compromises Zapier and ENS Ecosystems, Creates 22,000+ Malicious Repositories and counting Ashish Kurmi View LinkedIn November 23, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
The JavaScript ecosystem i…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1546** — Event Triggered Execution
- **T1543** — Create or Modify System Process
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1554** — Compromise Host Software Binary
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1555.006** — Credentials from Password Stores: Cloud Secrets Management Stores
- **T1526** — Cloud Service Discovery
- **T1567.001** — Exfiltration Over Web Service: Exfiltration to Code Repository
- **T1102.002** — Web Service: Bidirectional Communication
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1071.001** — Application Layer Protocols: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NPM preinstall hook fetching Bun installer from bun.sh (Sha1-Hulud dropper)

`UC_713_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent_name, values(Processes.process_name) as child_name, values(Processes.user) as user, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*bun.sh/install*" OR Processes.process="*irm bun.sh*iex*") by Processes.dest, Processes.user
| `drop_dm_object_name(Processes)`
| where match(parent_name,"(?i)^(node|npm|yarn|pnpm|bun)(\.exe|-cli\.js)?$") AND match(child_name,"(?i)^(curl|bash|sh|powershell|pwsh|cmd)(\.exe)?$")
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("bun.sh/install", "bun.sh/install.ps1")
| where FileName in~ ("curl.exe","curl","bash","sh","powershell.exe","pwsh.exe","cmd.exe")
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","npm-cli.js","yarn.exe","yarn","pnpm.exe","pnpm","bun.exe","bun")
   or InitiatingProcessCommandLine has_any ("setup_bun.js","preinstall")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentName = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ChildName  = FileName,
          ChildCmd   = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Bun/Node executing the Sha1-Hulud worm payload (setup_bun.js / bun_environment.js)

`UC_713_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent_name, values(Processes.process_name) as proc_name, values(Processes.user) as user, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*setup_bun.js*" OR Processes.process="*bun_environment.js*") by Processes.dest, Processes.user
| `drop_dm_object_name(Processes)`
| where match(proc_name,"(?i)^(node|bun)(\.exe)?$")
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("setup_bun.js","bun_environment.js")
| where FileName in~ ("node.exe","node","bun.exe","bun")
| where AccountName !endswith "$"
| extend HasBgMarker = InitiatingProcessCommandLine has "POSTINSTALL_BG"
           or ProcessCommandLine has "POSTINSTALL_BG"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentName = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          GrandparentName = InitiatingProcessParentFileName,
          HasBgMarker, SHA256
| order by Timestamp desc
```

### Sha1-Hulud self-hosted GitHub Actions runner deployed under ~/.dev-env (SHA1HULUD)

`UC_713_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(_time) as times, values(Filesystem.file_path) as path, values(Filesystem.process_name) as proc_name, values(Filesystem.user) as user, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="actions-runner-linux-x64-*.tar.gz" OR Filesystem.file_name="actions-runner-osx-*.tar.gz" OR Filesystem.file_name="actions-runner-win-*.zip") AND Filesystem.file_path="*/.dev-env/*" by Filesystem.dest, Filesystem.user
| `drop_dm_object_name(Filesystem)`
| append
  [| tstats summariesonly=t count, values(Processes.process) as cmdline, values(Processes.process_name) as proc_name, values(Processes.user) as user, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*SHA1HULUD*" AND (Processes.process="*Runner.Listener*" OR Processes.process="*config.sh*" OR Processes.process="*--name*SHA1HULUD*") by Processes.dest, Processes.user
  | `drop_dm_object_name(Processes)`]
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let RunnerArchiveWrite = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName matches regex @"(?i)^actions-runner-(linux|osx|win)-[a-z0-9]+-[\d\.]+\.(tar\.gz|zip)$"
    | where FolderPath has ".dev-env"
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
              Source = "runner_archive_write",
              Detail = strcat(FolderPath, "\\", FileName),
              InitiatingProcessFileName, InitiatingProcessCommandLine;
let RunnerProcess = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName has_any ("Runner.Listener","config.sh","config.cmd","run.sh","run.cmd")
             or InitiatingProcessFileName has_any ("Runner.Listener","config.sh","run.sh"))
      and (ProcessCommandLine has "SHA1HULUD" or InitiatingProcessCommandLine has "SHA1HULUD")
    | project Timestamp, DeviceName, AccountName,
              Source = "runner_sha1hulud_exec",
              Detail = ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine;
union RunnerArchiveWrite, RunnerProcess
| order by Timestamp desc
```

### Bun/Node initiating multi-cloud secret-manager enumeration burst (Sha1-Hulud aL0 harvest)

`UC_713_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, dc(All_Traffic.dest) as dest_count, values(All_Traffic.dest) as endpoints, values(All_Traffic.process_name) as proc_name, values(All_Traffic.user) as user, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*.secretsmanager.*.amazonaws.com" OR All_Traffic.dest="secretmanager.googleapis.com" OR All_Traffic.dest="*.vault.azure.net") AND (All_Traffic.process_name="bun.exe" OR All_Traffic.process_name="bun" OR All_Traffic.process_name="node.exe" OR All_Traffic.process_name="node") by All_Traffic.src, All_Traffic.user, span=10m
| `drop_dm_object_name(All_Traffic)`
| eval cloud_providers=mvfilter(match(endpoints,"secretsmanager|secretmanager.googleapis.com|vault.azure.net"))
| eval aws_hit=if(match(mvjoin(endpoints,","),"secretsmanager"),1,0)
| eval gcp_hit=if(match(mvjoin(endpoints,","),"secretmanager.googleapis.com"),1,0)
| eval azure_hit=if(match(mvjoin(endpoints,","),"vault.azure.net"),1,0)
| eval cloud_count=aws_hit+gcp_hit+azure_hit
| where cloud_count >= 2
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where InitiatingProcessFileName in~ ("bun.exe","bun","node.exe","node")
| where RemoteUrl matches regex @"(?i)(secretsmanager\.[a-z0-9-]+\.amazonaws\.com|secretmanager\.googleapis\.com|[a-z0-9-]+\.vault\.azure\.net)"
| extend Cloud = case(
    RemoteUrl has "secretsmanager.", "AWS",
    RemoteUrl has "secretmanager.googleapis.com", "GCP",
    RemoteUrl has ".vault.azure.net", "Azure",
    "other")
| summarize Endpoints = make_set(RemoteUrl, 50),
            Clouds   = make_set(Cloud, 5),
            HitCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
            by DeviceName, AccountName = InitiatingProcessAccountName,
               InitiatingProcessFileName, bin(Timestamp, 10m)
| where array_length(Clouds) >= 2
| order by FirstSeen desc
```

### Bun/Node bursty PUT to api.github.com /contents from infected host (Sha1-Hulud exfil)

`UC_713_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t min(_time) as InfectionTime values(Processes.dest) as InfectedHost from datamodel=Endpoint.Processes where (Processes.process="*bun_environment.js*" OR Processes.process="*setup_bun.js*") by Processes.dest
| `drop_dm_object_name(Processes)`
| join type=inner dest [
    | tstats summariesonly=t count as ApiHits, min(_time) as FirstApiHit, max(_time) as LastApiHit values(All_Traffic.dest) as endpoints from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="api.github.com" AND (All_Traffic.process_name="bun.exe" OR All_Traffic.process_name="bun" OR All_Traffic.process_name="node.exe" OR All_Traffic.process_name="node") by All_Traffic.dest, All_Traffic.src
    | `drop_dm_object_name(All_Traffic)`
    | rename src as dest]
| where FirstApiHit >= InfectionTime AND FirstApiHit <= InfectionTime + 3600 AND ApiHits >= 5
| convert ctime(InfectionTime), ctime(FirstApiHit), ctime(LastApiHit)
```

**Defender KQL:**
```kql
let Lookback = 24h;
let Infection = DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where ProcessCommandLine has_any ("bun_environment.js","setup_bun.js")
    | summarize InfectionTime = min(Timestamp) by DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(Lookback)
| where InitiatingProcessFileName in~ ("bun.exe","bun","node.exe","node")
| where RemoteUrl has "api.github.com"
| join kind=inner Infection on DeviceName
| where Timestamp between (InfectionTime .. InfectionTime + 1h)
| summarize ApiHits = count(),
            FirstHit = min(Timestamp),
            LastHit  = max(Timestamp),
            Endpoints = make_set(RemoteUrl, 25)
            by DeviceName, AccountName = InitiatingProcessAccountName,
               InitiatingProcessFileName, InfectionTime
| where ApiHits >= 5
| extend DelaySec = datetime_diff('second', FirstHit, InfectionTime)
| project DeviceName, AccountName, InfectionTime, FirstHit, LastHit, DelaySec, ApiHits, InitiatingProcessFileName, Endpoints
| order by FirstHit desc
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
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

### Article-specific behavioural hunt — Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Pac

`UC_713_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Pac ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bun_environment.js","setup_bun.js","bun.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/src/app*" OR Filesystem.file_path="*/root/.bun/bin/bun*" OR Filesystem.file_name IN ("bun_environment.js","setup_bun.js","bun.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Sha1-Hulud: The Second Coming - Zapier, ENS Domains, and Other Prominent NPM Pac
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bun_environment.js", "setup_bun.js", "bun.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/src/app", "/root/.bun/bin/bun") or FileName in~ ("bun_environment.js", "setup_bun.js", "bun.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 11 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
