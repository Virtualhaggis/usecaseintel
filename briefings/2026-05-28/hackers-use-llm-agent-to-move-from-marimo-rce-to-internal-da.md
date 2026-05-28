# [CRIT] Hackers Use LLM Agent to Move From Marimo RCE to Internal Database in Four Pivots

**Source:** Cyber Security News
**Published:** 2026-05-28
**Article:** https://cybersecuritynews.com/hackers-use-llm-agent-to-move-from-marimo-rce/

## Threat Profile

Home Cyber Security News 
Hackers Use LLM Agent to Move From Marimo RCE to Internal Database in Four Pivots 
By Tushar Subhra Dutta 
May 28, 2026 




A new kind of cyberattack is changing how defenders must think about intrusion detection. On May 10, 2026, a threat actor used a large language model (LLM) agent to drive a full post-exploitation chain, starting from an exposed notebook server and ending with an internal database dumped in under two minutes. 
This was not a pre-scripted attack…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-39987`
- **IPv4 (defanged):** `157.66.54.26`
- **IPv4 (defanged):** `104.28.162.160`
- **IPv4 (defanged):** `104.28.165.251`
- **IPv4 (defanged):** `104.28.165.169`
- **IPv4 (defanged):** `104.28.157.50`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1555.006** — Credentials from Password Stores: Cloud Secrets Management Stores
- **T1021.004** — Remote Services: SSH
- **T1005** — Data from Local System
- **T1213** — Data from Information Repositories
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] marimo notebook Python process spawning interactive shell (CVE-2026-39987 post-exploit)

`UC_1_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python3","uvicorn") OR Processes.parent_process="*marimo*") Processes.process_name IN ("bash","sh","dash","zsh","ksh") by host, Processes.user, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | where like(parent_process,"%marimo%") OR like(process,"%id%") OR like(process,"%whoami%") OR like(process,"%/.aws/credentials%") OR like(process,"%/.pgpass%")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python","python3","uvicorn") or InitiatingProcessCommandLine has "marimo"
| where FileName in~ ("bash","sh","dash","zsh","ksh")
| where InitiatingProcessCommandLine has "marimo" or ProcessCommandLine has_any ("id","whoami","/.aws/credentials","/.pgpass","env","find /","ls /")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Burst AWS API calls fanned across Cloudflare Workers egress (104.28.0.0/16) for one principal

`UC_1_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" by All_Changes.user, All_Changes.src, All_Changes.action, _time span=2m | `drop_dm_object_name(All_Changes)` | where cidrmatch("104.28.0.0/16", src) | stats dc(src) as distinct_src_ips, dc(action) as distinct_actions, sum(count) as api_calls, values(src) as src_ips, values(action) as actions by user, _time | where distinct_src_ips >= 5 AND api_calls >= 10
```

### [LLM] AWS Secrets Manager retrieval from Cloudflare Workers egress pool

`UC_1_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.action IN ("GetSecretValue","ListSecrets") by All_Changes.user, All_Changes.src, All_Changes.action, All_Changes.object, _time | `drop_dm_object_name(All_Changes)` | where cidrmatch("104.28.0.0/16", src) | stats min(_time) as firstTime max(_time) as lastTime values(action) as actions values(object) as secrets values(src) as src_ips count by user
```

### [LLM] SSH authentication to bastion from Cloudflare Workers CIDR (104.28.0.0/16)

`UC_1_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Authentication where Authentication.app=sshd Authentication.action=success by Authentication.src, Authentication.user, Authentication.dest, _time span=10m | `drop_dm_object_name(Authentication)` | where cidrmatch("104.28.0.0/16", src) | stats dc(src) as src_count sum(count) as session_count values(src) as src_ips by user, dest, bin_time | where src_count >= 3 OR session_count >= 5
```

**Defender KQL:**
```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where Protocol == "Ssh" or InitiatingProcessFileName =~ "sshd"
| where ipv4_is_in_range(RemoteIP, "104.28.0.0/16")
| summarize SessionCount = count(), SrcIPs = make_set(RemoteIP), DistinctSrc = dcount(RemoteIP), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, AccountName, bin(Timestamp, 10m)
| where DistinctSrc >= 3 or SessionCount >= 5
| order by LastSeen desc
```

### [LLM] PostgreSQL HEREDOC credential-table dump invoked from compromised host

`UC_1_10` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("psql","pg_dump") by host, Processes.user, Processes.process, Processes.parent_process_name, _time | `drop_dm_object_name(Processes)` | where match(process,"(?i)(credentials|password|users|secrets|tokens|api_keys)") OR match(process,"<<\s*[A-Z_]+") OR match(process,"(?i)copy\s+\(?\s*select") | join type=left host, user [| tstats summariesonly=true count as pgpass_reads from datamodel=Endpoint.Filesystem where Filesystem.file_name=".pgpass" by host, Filesystem.user | rename Filesystem.user as user | `drop_dm_object_name(Filesystem)`] | table _time host user process parent_process_name pgpass_reads
```

**Defender KQL:**
```kql
let PgpassReaders = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName == ".pgpass" or FolderPath endswith "/.pgpass"
    | where ActionType in ("FileOpenedForRead","FileCreated","FileModified")
    | project PgpassTime = Timestamp, DeviceId, InitiatingProcessAccountName, InitiatingProcessId;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psql","pg_dump")
| where ProcessCommandLine matches regex @"(?i)(credentials|password|users|secrets|tokens|api_keys)"
   or ProcessCommandLine matches regex @"<<\s*[A-Z_]+"
   or ProcessCommandLine matches regex @"(?i)copy\s+\(?\s*select"
| join kind=leftouter PgpassReaders on DeviceId, $left.AccountName == $right.InitiatingProcessAccountName
| where isnotempty(PgpassTime) or ProcessCommandLine has_any ("credentials","users","<<")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, PgpassTime
| order by Timestamp desc
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

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-39987`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `157.66.54.26`, `104.28.162.160`, `104.28.165.251`, `104.28.165.169`, `104.28.157.50`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
