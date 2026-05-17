# [CRIT] Grafana GitHub Token Breach Led to Codebase Download and Extortion Attempt

**Source:** The Hacker News
**Published:** 2026-05-17
**Article:** https://thehackernews.com/2026/05/grafana-github-token-breach-led-to.html

## Threat Profile

Grafana GitHub Token Breach Led to Codebase Download and Extortion Attempt 
 Ravie Lakshmanan  May 17, 2026 Data Breach / Cybercrime 
Grafana has disclosed that an "unauthorized party" obtained a token that granted them the ability to access the company's GitHub environment and download its codebase.
"Our investigation has determined that no customer data or personal information was accessed during this incident, and we have found no evidence of impact to customer systems or operations," Grafa…

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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1528** — Steal Application Access Token
- **T1199** — Trusted Relationship
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1119** — Automated Collection
- **T1530** — Data from Cloud Storage
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Anomalous GitHub authentication from new ASN/anonymizer — CoinbaseCartel stolen-token access

`UC_3_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.user_agent) as user_agent from datamodel=Authentication where Authentication.app IN ("github","github_enterprise","GitHub*") Authentication.action=success by Authentication.user Authentication.src_ip Authentication.src_geo Authentication.signature | `drop_dm_object_name(Authentication)` | iplocation src_ip | search (NOT src_geo IN ("United States","Germany","United Kingdom","Ireland") OR match(signature,"(?i)tor|hosting|datacenter|vpn|proxy")) | join type=outer user [| tstats `summariesonly` values(Authentication.src_geo) as historical_geo earliest=-30d@d latest=-1d@d from datamodel=Authentication where Authentication.app IN ("github","github_enterprise") Authentication.action=success by Authentication.user | `drop_dm_object_name(Authentication)`] | where NOT (src_geo IN historical_geo) | table firstTime user src_ip src_geo user_agent signature historical_geo
```

**Defender KQL:**
```kql
let lookback = 30d;
let recent = 1h;
let baseline = CloudAppEvents
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where Application has "GitHub"
    | where ActionType in~ ("Login attempt","Authenticated","User logged in","Successful login")
    | summarize KnownCountries = make_set(CountryCode), KnownISPs = make_set(ISP) by AccountObjectId;
CloudAppEvents
| where Timestamp > ago(recent)
| where Application has "GitHub"
| where ActionType in~ ("Login attempt","Authenticated","User logged in","Successful login")
| join kind=leftouter baseline on AccountObjectId
| where IsAnonymousProxy == true
   or CountryCode !in (KnownCountries)
   or (isnotempty(ISP) and ISP !in (KnownISPs) and ISP has_any ("DigitalOcean","Hetzner","OVH","Mullvad","NordVPN","Surfshark","M247","Choopa","Tor","Vultr"))
| project Timestamp, AccountDisplayName, AccountObjectId, Application, ActionType,
          IPAddress, CountryCode, City, ISP, IsAnonymousProxy, UserAgent,
          KnownCountries, KnownISPs, AdditionalFields
| order by Timestamp desc
```

### [LLM] Bulk GitHub repository download/clone burst from single identity

`UC_3_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as cloneCount dc(Web.url) as repoCount values(Web.url) as repos values(Web.src) as src_ips values(Web.http_user_agent) as user_agents min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.dest_domain IN ("api.github.com","codeload.github.com","github.com") AND (Web.url="*git-upload-pack*" OR Web.url="*/archive/*.zip" OR Web.url="*/archive/refs/heads/*" OR Web.url="*/zipball/*" OR Web.url="*/tarball/*")) by Web.user Web.src span=1h | `drop_dm_object_name(Web)` | where repoCount >= 20 | eval bytesEstimate=cloneCount*"50MB" | table firstTime lastTime user src repoCount cloneCount user_agents src_ips repos
```

**Defender KQL:**
```kql
let window = 1h;
let bulk_threshold = 20;
CloudAppEvents
| where Timestamp > ago(24h)
| where Application has "GitHub"
| where ActionType in~ ("git.clone","git.fetch","repo.download_zip","repo.download_tarball","repo.access")
   or ActivityType in~ ("git.clone","repo.download_zip")
| extend Repo = coalesce(ObjectName, tostring(parse_json(tostring(RawEventData)).repository))
| where isnotempty(Repo)
| summarize RepoCount = dcount(Repo),
            Repos = make_set(Repo, 50),
            ActionCount = count(),
            SrcIPs = make_set(IPAddress, 20),
            Countries = make_set(CountryCode, 10),
            UserAgents = make_set(UserAgent, 10),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by AccountObjectId, AccountDisplayName, bin(Timestamp, window)
| where RepoCount >= bulk_threshold
| extend BurstWindowMin = datetime_diff('minute', LastSeen, FirstSeen)
| project FirstSeen, LastSeen, BurstWindowMin, AccountDisplayName, AccountObjectId,
          RepoCount, ActionCount, Repos, SrcIPs, Countries, UserAgents
| order by RepoCount desc
```

### [LLM] Helpdesk MFA reset on engineering account followed by GitHub access — ShinyHunters/Scattered Spider playbook

`UC_3_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as resetTime values(Change.src) as resetSrc values(Change.result) as result from datamodel=Change where Change.action=modified Change.object_category=user (Change.change_type="AuthMethod*" OR Change.command IN ("Reset user password","Update authentication method","User registered security info","Admin registered security info")) by Change.user Change.src_user | `drop_dm_object_name(Change)` | rename user as target_user, src_user as helpdesk_actor | join type=inner target_user [| tstats `summariesonly` min(_time) as ghTime values(Authentication.src) as ghSrc from datamodel=Authentication where Authentication.app IN ("github","github_enterprise") Authentication.action=success earliest=-1d by Authentication.user | rename Authentication.user as target_user | `drop_dm_object_name(Authentication)`] | eval delaySec=ghTime-resetTime | where delaySec>=0 AND delaySec<=14400 | table resetTime ghTime delaySec helpdesk_actor target_user resetSrc ghSrc
```

**Defender KQL:**
```kql
let window = 4h;
let mfa_resets = IdentityDirectoryEvents
    | where Timestamp > ago(24h)
    | where ActionType in~ ("Password reset","Forced password reset","User registered security info","Admin registered security info","Update user","Authentication method registered","Authentication method removed")
    | extend TargetUpn = tolower(TargetAccountUpn),
             InitiatorUpn = tolower(AccountUpn)
    | where TargetUpn != InitiatorUpn
    | project ResetTime = Timestamp, TargetUpn, InitiatorUpn, ResetAction = ActionType, ResetIp = IPAddress, AdditionalFields;
AADSignInEventsBeta
| where Timestamp > ago(24h)
| where Application has "GitHub" or ResourceDisplayName has "GitHub"
| where ErrorCode == 0
| extend TargetUpn = tolower(AccountUpn)
| join kind=inner mfa_resets on TargetUpn
| where Timestamp between (ResetTime .. ResetTime + window)
| extend DelayMin = datetime_diff('minute', Timestamp, ResetTime)
| project ResetTime, GitHubAuthTime = Timestamp, DelayMin,
          TargetUpn, InitiatorUpn, ResetAction, ResetIp,
          GitHubIp = IPAddress, GitHubCountry = Country, GitHubCity = City,
          GitHubUA = UserAgent, GitHubApp = Application
| order by GitHubAuthTime desc
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


## Why this matters

Severity classified as **CRIT** based on: 10 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
