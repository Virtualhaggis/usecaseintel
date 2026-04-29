# [HIGH] Checkmarx confirms LAPSUS$ hackers leaked its stolen GitHub data

**Source:** BleepingComputer
**Published:** 2026-04-28
**Article:** https://www.bleepingcomputer.com/news/security/checkmarx-confirms-lapsus-hackers-leaked-its-stolen-github-data/

## Threat Profile

Checkmarx confirms LAPSUS$ hackers leaked its stolen GitHub data 
By Bill Toulas 
April 28, 2026
10:50 AM
0 
Application security company Checkmarx has confirmed that the LAPSUS$ threat group leaked data stolen from its private GitHub repository.
Although the investigation is ongoing, Checkmarx believes that the access vector was the  Trivy supply-chain attack  attributed to the hacker group known as TeamPCP. which provided access to credentials from downstream users.
Using stolen credentials ob…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1567.002** — Exfiltration to Cloud Storage / Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain
- **T1610** — Deploy Container
- **T1554** — Compromise Host Software Binary
- **T1567** — Exfiltration Over Web Service
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### [LLM] TeamPCP/LAPSUS$ exfil to checkmarx[.]zone / audit.checkmarx[.]cx via KICS-Telemetry UA

`UC_22_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("checkmarx.zone","*.checkmarx.zone","audit.checkmarx.cx","scan.aquasecurtiy.org") OR All_Traffic.dest_ip IN ("45.148.10.212","94.154.172.43")) by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.app | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url from datamodel=Web.Web where Web.http_user_agent="KICS-Telemetry/2.0" by Web.src Web.dest Web.http_user_agent | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badHosts = dynamic(["checkmarx.zone","audit.checkmarx.cx","scan.aquasecurtiy.org"]);
let badIPs   = dynamic(["45.148.10.212","94.154.172.43"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (badHosts)) or (RemoteIP in (badIPs))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| union (
  DeviceEvents
  | where ActionType == "BrowserLaunchedToOpenUrl" or AdditionalFields has "KICS-Telemetry/2.0"
  | project Timestamp, DeviceName, AdditionalFields, InitiatingProcessFileName)
```

### [LLM] Pull or run of poisoned checkmarx/kics Docker tags (v2.1.21 / overwritten v2.1.20 / latest)

`UC_22_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_name IN ("docker.exe","docker","podman","podman.exe","buildx","nerdctl","crictl","skopeo") AND (Processes.process="*checkmarx/kics:v2.1.21*" OR Processes.process="*checkmarx/kics:v2.1.21-debian*" OR Processes.process="*checkmarx/kics:latest*" OR Processes.process="*checkmarx/kics:v2.1.20*" OR Processes.process="*checkmarx/kics:v2.1.20-debian*" OR Processes.process="*checkmarx/kics:alpine*" OR Processes.process="*checkmarx/kics:debian*") by Processes.user Processes.dest Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | eval malicious_window=if(firstTime>=strptime("2026-04-22 14:00:00","%Y-%m-%d %H:%M:%S") AND firstTime<=strptime("2026-04-23 00:00:00","%Y-%m-%d %H:%M:%S"),"WITHIN-COMPROMISE-WINDOW","REVIEW") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let badTags = dynamic(["checkmarx/kics:v2.1.21","checkmarx/kics:v2.1.21-debian","checkmarx/kics:latest","checkmarx/kics:v2.1.20","checkmarx/kics:v2.1.20-debian","checkmarx/kics:alpine","checkmarx/kics:debian"]);
DeviceProcessEvents
| where Timestamp > datetime(2026-04-22)
| where FileName in~ ("docker.exe","docker","podman","podman.exe","buildx.exe","nerdctl","crictl","skopeo")
| where ProcessCommandLine has_any (badTags)
| extend InWindow = iff(Timestamp between (datetime(2026-04-22T14:17:00Z) .. datetime(2026-04-22T15:41:00Z)),"PULL-DURING-COMPROMISE","REVIEW")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InWindow
| union (
    DeviceFileEvents
    | where Timestamp > datetime(2026-04-22)
    | where FolderPath has ".vscode" or FolderPath has "open-vsx" or FolderPath has "extensions"
    | where FileName has_any ("checkmarx-ast-results-1.17.0","checkmarx-ast-results-1.19.0","checkmarx-kics")
    | project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine)
```

### [LLM] TeamPCP fallback exfil: creation of 'tpcp-docs' repository in GitHub org

`UC_22_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process_name IN ("git.exe","git","gh.exe","gh","curl.exe","curl","wget","python.exe","python","node.exe","node")) AND (Processes.process="*tpcp-docs*") by Processes.user Processes.dest Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=t count from datamodel=Web.Web where Web.url="*api.github.com/user/repos*" OR Web.url="*api.github.com/orgs/*/repos*" by Web.src Web.dest Web.url Web.http_user_agent | search url="*tpcp-docs*" | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where ProcessCommandLine has "tpcp-docs"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| union (
    DeviceNetworkEvents
    | where Timestamp > ago(60d)
    | where RemoteUrl has "api.github.com"
    | where InitiatingProcessCommandLine has "tpcp-docs" or AdditionalFields has "tpcp-docs"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
  )
| union (
    DeviceFileEvents
    | where Timestamp > ago(60d)
    | where FileName endswith ".pth" or FolderPath has "site-packages"
    | where FileName has "litellm" and (FileName has "1.82.7" or FileName has "1.82.8")
    | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName)
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
