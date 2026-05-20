# [HIGH] Grafana says stolen GitHub token let hackers steal codebase

**Source:** BleepingComputer
**Published:** 2026-05-18
**Article:** https://www.bleepingcomputer.com/news/security/grafana-says-stolen-github-token-let-hackers-steal-codebase/

## Threat Profile

Grafana says stolen GitHub token let hackers steal codebase 
By Bill Toulas 
May 18, 2026
09:46 AM
0 
Grafana Labs disclosed that hackers have downloaded its source code after breaching its GitHub environment using a stolen access token.
A relatively new extortion gang known as CoinbaseCartel has claimed the attack by adding Grafana to their data leak site (DLS), although no data has been leaked yet.
Grafana Labs is the company behind Grafana, the popular open-source platform for analytics, moni…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1199** — Trusted Relationship
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1567** — Exfiltration Over Web Service
- **T1119** — Automated Collection
- **T1070.004** — Indicator Removal: File Deletion
- **T1070** — Indicator Removal
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1490** — Inhibit System Recovery
- **T1486** — Data Encrypted for Impact
- **T1529** — System Shutdown/Reboot
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GitHub Actions 'Pwn Request' — forked PR triggers pull_request_target workflow with secret exfiltration

`UC_20_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Change.object) as repo values(Change.object_attrs.head_repository.full_name) as forkRepo values(Change.object_attrs.head_repository.fork) as isFork values(Change.object_attrs.event) as triggerEvent values(Change.user) as actor values(Change.src) as src from datamodel=Change.All_Changes where Change.object_category="github_workflow_run" Change.action="started" Change.object_attrs.event="pull_request_target" Change.object_attrs.head_repository.fork="true" by Change.object_id Change.user _time span=5m | `drop_dm_object_name(Change)` | join type=inner object_id [| tstats `summariesonly` count from datamodel=Change.All_Changes where Change.object_category="github_workflow_job" (Change.object_attrs.steps.run="*curl*" OR Change.object_attrs.steps.run="*wget*" OR Change.object_attrs.steps.run="*env*>*" OR Change.object_attrs.steps.run="*printenv*" OR Change.object_attrs.steps.run="*${{*secrets*" OR Change.object_attrs.steps.run="*openssl*enc*") by Change.object_id | rename Change.object_id as object_id | fields object_id] | where isFork="true" | table firstSeen actor repo forkRepo triggerEvent src
```

**Defender KQL:**
```kql
// CloudAppEvents requires GitHub connected to Microsoft Defender for Cloud Apps; otherwise this UC is GitHub-audit-only and Defender XDR cannot see it.
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "GitHub"
| where ActionType in ("workflow_run.started", "workflows.completed_workflow_run", "workflow_job.completed")
| extend Event = tostring(RawEventData.workflow_run.event)
| extend ForkSource = tobool(RawEventData.workflow_run.head_repository.fork)
| extend HeadRepo = tostring(RawEventData.workflow_run.head_repository.full_name)
| extend BaseRepo = tostring(RawEventData.workflow_run.repository.full_name)
| extend StepsRaw = tostring(RawEventData)
| where Event == "pull_request_target" and ForkSource == true
| where StepsRaw has_any ("curl ", "wget ", "printenv", "${{ secrets", "env >", "openssl enc")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, BaseRepo, HeadRepo, Event, StepsRaw
```

### [LLM] GitHub PAT mass private-repo clone burst from a single actor

`UC_20_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Web.url) as repoCount values(Web.url) as repos values(Web.src) as srcIPs values(Web.http_user_agent) as userAgents min(_time) as firstSeen max(_time) as lastSeen from datamodel=Web.Web where Web.app="github" Web.action IN ("git.clone","repo.download_zip","repo.archive_downloaded") Web.dest_category="private" by Web.user _time span=10m | `drop_dm_object_name(Web)` | where repoCount >= 3 | eval cloneRatePerMin = round(count / 10.0, 2) | where cloneRatePerMin > 0.3 | table firstSeen lastSeen user repoCount repos srcIPs userAgents cloneRatePerMin
```

**Defender KQL:**
```kql
// GitHub audit data is generally not native to Defender XDR. If GitHub Enterprise is connected to Microsoft Defender for Cloud Apps the events surface in CloudAppEvents.
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "GitHub"
| where ActionType in ("git.clone", "repo.download_zip", "repository.archive_downloaded")
| extend RepoName = tostring(RawEventData.repo)
| extend RepoVisibility = tostring(RawEventData.repository.visibility)
| where RepoVisibility =~ "private"
| summarize RepoCount = dcount(RepoName), Repos = make_set(RepoName, 50), SrcIPs = make_set(IPAddress, 10), UAs = make_set(UserAgent, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, bin(Timestamp, 10m)
| where RepoCount >= 3
| order by FirstSeen desc
```

### [LLM] GitHub fork-then-delete by external account immediately after privileged workflow run

`UC_20_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(_time) as eventTimes values(Change.action) as actions values(Change.object) as forkRepo values(Change.object_attrs.parent.full_name) as parentRepo values(Change.user) as actor values(Change.src) as src from datamodel=Change.All_Changes where Change.object_category="github_repository" Change.object_attrs.fork="true" Change.action IN ("repo.create","repo.destroy") by Change.object_id _time span=1d | `drop_dm_object_name(Change)` | where mvcount(actions)=2 AND mvfind(actions,"repo.create")>=0 AND mvfind(actions,"repo.destroy")>=0 | eval lifespanSec = abs(round(mvindex(eventTimes,1) - mvindex(eventTimes,0))) | where lifespanSec < 86400 | table actor forkRepo parentRepo lifespanSec eventTimes src
```

**Defender KQL:**
```kql
// Requires GitHub connected via Defender for Cloud Apps; otherwise out of scope for Defender XDR.
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "GitHub"
| where ActionType in ("repo.create", "repository.create", "repo.destroy", "repository.destroy")
| extend RepoName = tostring(RawEventData.repo)
| extend IsFork = tobool(RawEventData.repository.fork)
| extend ParentRepo = tostring(RawEventData.repository.parent.full_name)
| where IsFork == true
| summarize Actions = make_set(ActionType), EventTimes = make_list(Timestamp), Parents = make_set(ParentRepo) by AccountObjectId, AccountDisplayName, RepoName
| where array_length(Actions) == 2 and Actions has "repo.create" and Actions has "repo.destroy"
| extend LifespanSec = datetime_diff("second", todatetime(EventTimes[1]), todatetime(EventTimes[0]))
| where abs(LifespanSec) < 86400
| project AccountDisplayName, AccountObjectId, RepoName, Parents, LifespanSec, EventTimes
```

### [LLM] ShinySp1d3r ESXi — mass snapshot deletion immediately followed by VMDK rename/write

`UC_20_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Processes.process) as cmdVariants values(Processes.process) as cmds values(Processes.dest) as esxiHost values(Processes.user) as user min(_time) as firstSeen max(_time) as lastSeen from datamodel=Endpoint.Processes where (Processes.process="*vim-cmd*vmsvc/snapshot.removeall*" OR Processes.process="*vim-cmd*vmsvc/power.off*" OR Processes.process="*esxcli*vm*process*kill*" OR Processes.process="*esxcli*storage*filesystem*list*") by Processes.dest _time span=5m | `drop_dm_object_name(Processes)` | where cmdVariants >= 2 | join type=inner dest [| tstats `summariesonly` count values(Filesystem.file_path) as encryptedFiles from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*.vmdk" OR Filesystem.file_name="*.vmdk.encrypted" OR Filesystem.file_name="*.vmdk.shiny*" OR Filesystem.action="renamed") Filesystem.file_create_time > now()-600 by Filesystem.dest | rename Filesystem.dest as dest | fields dest encryptedFiles] | table firstSeen lastSeen esxiHost user cmdVariants cmds encryptedFiles
```

**Defender KQL:**
```kql
// ShinySp1d3r executes ON the ESXi hypervisor — Defender for Endpoint does not cover ESXi natively. Pivoting to the Windows/Linux jump host that staged the SSH/PowerCLI session is the closest Defender-side signal.
let WindowMinutes = 10m;
let EsxiCmdHosts = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (FileName =~ "ssh.exe" or FileName =~ "plink.exe" or FileName =~ "powershell.exe" or FileName =~ "pwsh.exe")
    | where ProcessCommandLine has_any ("vim-cmd vmsvc/snapshot.removeall", "vim-cmd vmsvc/power.off", "esxcli vm process kill", "Get-VM", "Remove-Snapshot", "Stop-VM -Confirm:$false", "Set-VM -RunAsync")
    | project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName;
EsxiCmdHosts
| summarize CmdHits = count(), Cmds = make_set(ProcessCommandLine, 20), Users = make_set(AccountName, 5), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceId, DeviceName, bin(Timestamp, WindowMinutes)
| where CmdHits >= 3
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort in (22, 443, 902, 903, 5988, 5989)
    | where InitiatingProcessFileName in~ ("ssh.exe", "plink.exe", "powershell.exe", "pwsh.exe")
    | summarize EsxiTargets = make_set(RemoteIP, 20) by DeviceId
) on DeviceId
| project FirstSeen, LastSeen, DeviceName, Users, CmdHits, Cmds, EsxiTargets
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

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
    | where AccountName !endswith "$"
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
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
