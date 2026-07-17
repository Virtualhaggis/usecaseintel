# [HIGH] The AntV Supply Chain Campaign Expands: Microsoft's `durabletask` PyPI Package Compromised

**Source:** Snyk
**Published:** 2026-05-19
**Article:** https://snyk.io/blog/durabletask-pypi-supply-chain-attack/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
May 19, 2026
0 mins read The ink was barely dry on our coverage of the AntV Shai Hulud supply chain attack when a new compromise surfaced in the Python ecosystem. The target this time is durabletask , an open source Python package associated with Microsoft, used for building durable, fault-tolerant workflow orchestration on top of the Durable Task Framework.
The latest safe version of durabletask is 1.4.0 , and three known versions have been yanked…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `160.119.64.3`
- **IPv4 (defanged):** `185.95.159.32`
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

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.007** — Remote Services: Cloud Services
- **T1651** — Cloud Administration Command
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1552.001** — Unsecured Credentials: Credentials in Files
- **T1555.005** — Credentials from Password Stores
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Compromised Microsoft durabletask PyPI Package Install (TeamPCP 1.4.1-1.4.3)

`UC_382_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

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

`UC_382_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

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

`UC_382_8` · phase: **install** · confidence: **High** · AI-generated for this article

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

`UC_382_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

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

`UC_382_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `160.119.64.3`, `185.95.159.32`, `check.git-service.com`, `t.m-kosche.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce`, `7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8`, `3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf`, `aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5`, `85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f`, `877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec`, `c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
