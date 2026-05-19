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
- **T1213.003** — Code Repositories
- **T1567** — Exfiltration Over Web Service
- **T1528** — Steal Application Access Token
- **T1078.004** — Cloud Accounts
- **T1550.001** — Application Access Token
- **T1535** — Unused/Unsupported Cloud Regions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GitHub PAT/OAuth token bulk repository clone or download burst (CoinbaseCartel-style codebase theft)

`UC_13_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Changes.object) as repo_count, values(All_Changes.object) as repos, values(All_Changes.src) as src_ips, values(All_Changes.user_agent) as user_agents from datamodel=Change where All_Changes.vendor_product="GitHub" AND All_Changes.action IN ("repo.clone","repo.download_zip","git.clone","git.fetch","repo.archive") by All_Changes.user, _time span=10m | `drop_dm_object_name(All_Changes)` | where repo_count >= 15 | sort - repo_count
```

**Defender KQL:**
```kql
let WindowMin = 10m;
let CloneActions = dynamic(["Repo cloned","Repository cloned","Repo downloaded as ZIP","git.clone","git.fetch","repo.clone","repo.download_zip","repo.archive"]);
CloudAppEvents
| where Timestamp > ago(1d)
| where Application has "GitHub"
| where ActionType in~ (CloneActions) or AdditionalFields has_any (CloneActions)
| extend RepoName = tostring(parse_json(tostring(ActivityObjects))[0].Name),
         AppInst = tostring(AppInstanceId)
| summarize RepoCount = dcount(RepoName),
            EventCount = count(),
            Repos = make_set(RepoName, 50),
            SrcIPs = make_set(IPAddress, 10),
            Countries = make_set(CountryCode, 10),
            UserAgents = make_set(UserAgent, 5),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
          by AccountObjectId, AccountDisplayName, bin(Timestamp, WindowMin)
| where RepoCount >= 15
| where not(AccountDisplayName has_any ("github-actions","dependabot","renovate","backup"))
| order by RepoCount desc
```

### [LLM] GitHub PAT/OAuth token used from first-time IP or country (stolen-token reuse)

`UC_13_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as first_seen, count from datamodel=Authentication where Authentication.app="GitHub" AND Authentication.action="success" by Authentication.user, Authentication.src, Authentication.src_country | `drop_dm_object_name(Authentication)` | where first_seen >= relative_time(now(), "-1h") | join type=left user [| tstats `summariesonly` count as baseline_count, values(Authentication.src_country) as baseline_countries from datamodel=Authentication where earliest=-30d@d latest=-1h Authentication.app="GitHub" by Authentication.user | `drop_dm_object_name(Authentication)`] | where baseline_count > 10 AND NOT match(baseline_countries, src_country) | table first_seen, user, src, src_country, baseline_countries, count
```

**Defender KQL:**
```kql
let Lookback = 30d;
let Recent = 1h;
let GitHubAuth = CloudAppEvents
    | where Application has "GitHub"
    | where ActionType in~ ("Log on","LogOn","Sign in","user.login","oauth_access.create","personal_access_token.access_granted","git.clone","git.fetch","repo.clone");
let Baseline = GitHubAuth
    | where Timestamp between (ago(Lookback) .. ago(Recent))
    | summarize BaselineEvents = count(),
                BaselineIPs = make_set(IPAddress, 200),
                BaselineCountries = make_set(CountryCode, 50)
              by AccountObjectId
    | where BaselineEvents >= 10;
GitHubAuth
| where Timestamp > ago(Recent)
| summarize RecentEvents = count(),
            FirstSeen = min(Timestamp),
            RepoTargets = dcount(tostring(parse_json(tostring(ActivityObjects))[0].Name))
          by AccountObjectId, AccountDisplayName, IPAddress, CountryCode, City, ISP, UserAgent
| join kind=inner Baseline on AccountObjectId
| where IPAddress !in (BaselineIPs)
| where CountryCode !in (BaselineCountries) or array_length(BaselineCountries) == 0
| where not(ISP has_any ("Microsoft","GitHub","Azure"))
| project FirstSeen, AccountDisplayName, IPAddress, CountryCode, City, ISP, UserAgent, RecentEvents, RepoTargets, BaselineCountries
| order by RepoTargets desc, FirstSeen desc
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

Severity classified as **HIGH** based on: 5 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
