# [CRIT] Cracks in the Bedrock: Agent God Mode

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-04-08
**Article:** https://unit42.paloaltonetworks.com/exploit-of-aws-agentcore-iam-god-mode/

## Threat Profile

Threat Research Center 
Threat Research 
Malware 
Malware 
Cracks in the Bedrock: Agent God Mode 
8 min read 
Related Products Cortex Cortex Cloud Unit 42 AI Security Assessment Unit 42 Cloud Security Assessment Unit 42 Incident Response 
By: Ori Hadad 
Published: April 8, 2026 
Categories: Malware 
Threat Research 
Tags: Agentcore 
AI agents 
AWS 
Bedrock 
DNS tunneling 
Exfiltration 
IAM 
Identity 
Killchain 
Privilege escalation 
Sandbox 
Executive Summary 
Our first article about the boundar…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1071.004** — DNS
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1530** — Data from Cloud Storage
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1213** — Data from Information Repositories
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1548** — Abuse Elevation Control Mechanism
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
           AND All_Email.is_internal!="true"
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
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### [LLM] AgentCore SDK auto-create runtime role pulling ECR images (cross-account image exfil)

`UC_134_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as commands values(All_Changes.object) as ecr_targets values(All_Changes.src) as src_ips from datamodel=Change where (All_Changes.vendor_product="AWS CloudTrail" OR sourcetype="aws:cloudtrail") All_Changes.user="AmazonBedrockAgentCoreSDKRuntime-*" All_Changes.command IN ("GetAuthorizationToken","BatchGetImage","GetDownloadUrlForLayer","DescribeRepositories","ListImages") by All_Changes.user All_Changes.vendor_account span=1h
| `drop_dm_object_name(All_Changes)`
| rex field=ecr_targets max_match=0 "repository/(?<repo_names>[^\"\s,]+)"
| eval distinct_repos=mvcount(mvdedup(repo_names))
| where (mvfind(commands,"BatchGetImage")>=0 OR mvfind(commands,"GetDownloadUrlForLayer")>=0) AND (distinct_repos>1 OR mvfind(commands,"DescribeRepositories")>=0)
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Application has "Amazon Web Services" or ApplicationId == 11161
| where ActionType in ("GetAuthorizationToken","BatchGetImage","GetDownloadUrlForLayer","DescribeRepositories","ListImages")
| extend Raw = todynamic(RawEventData)
| extend SessionRole = tostring(Raw.userIdentity.sessionContext.sessionIssuer.userName)
| where SessionRole startswith "AmazonBedrockAgentCoreSDKRuntime-"
| extend TargetRepo = extract(@"repository/([A-Za-z0-9._/-]+)", 1, tostring(Raw.requestParameters))
| summarize Commands=make_set(ActionType), Repos=make_set(TargetRepo), DistinctRepos=dcount(TargetRepo), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SessionRole, IPAddress, AccountObjectId
| where Commands has_any ("BatchGetImage","GetDownloadUrlForLayer") and (DistinctRepos > 1 or Commands has "DescribeRepositories")
```

### [LLM] AgentCore execution role reading memory resources of another agent

`UC_134_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as commands values(All_Changes.object) as memory_arns from datamodel=Change where (All_Changes.vendor_product="AWS CloudTrail" OR sourcetype="aws:cloudtrail") All_Changes.user="AmazonBedrockAgentCoreSDKRuntime-*" All_Changes.command IN ("GetMemoryRecord","RetrieveMemoryRecords","ListMemoryRecords","ListSessions","ListEvents","ListActors","GetEvent") by All_Changes.user All_Changes.src All_Changes.vendor_account span=1h
| `drop_dm_object_name(All_Changes)`
| rex field=memory_arns max_match=0 "memory/(?<memory_ids>[A-Za-z0-9_-]+)"
| eval distinct_memories=mvcount(mvdedup(memory_ids))
| where distinct_memories>1 OR mvfind(commands,"ListMemoryRecords")>=0
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Application has "Amazon Web Services" or ApplicationId == 11161
| where ActionType in ("GetMemoryRecord","RetrieveMemoryRecords","ListMemoryRecords","ListSessions","ListEvents","ListActors","GetEvent")
| extend Raw = todynamic(RawEventData)
| extend SessionRole = tostring(Raw.userIdentity.sessionContext.sessionIssuer.userName)
| where SessionRole startswith "AmazonBedrockAgentCoreSDKRuntime-"
| extend MemoryId = coalesce(tostring(Raw.requestParameters.memoryId), extract(@"memory/([A-Za-z0-9_-]+)", 1, tostring(Raw.requestParameters)))
| summarize Commands=make_set(ActionType), Memories=make_set(MemoryId), DistinctMemories=dcount(MemoryId), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SessionRole, IPAddress, AccountObjectId
| where DistinctMemories > 1 or Commands has "ListMemoryRecords"
```

### [LLM] AgentCore SDK runtime role invoking a foreign Bedrock AgentCore runtime

`UC_134_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as runtime_arns values(All_Changes.src) as src_ips from datamodel=Change where (All_Changes.vendor_product="AWS CloudTrail" OR sourcetype="aws:cloudtrail") All_Changes.user="AmazonBedrockAgentCoreSDKRuntime-*" All_Changes.command IN ("InvokeAgentRuntime","InvokeCodeInterpreter","StartCodeInterpreterSession","ListAgentRuntimes","ListCodeInterpreters") by All_Changes.user All_Changes.command All_Changes.vendor_account span=1h
| `drop_dm_object_name(All_Changes)`
| rex field=user "AmazonBedrockAgentCoreSDKRuntime-(?<role_region>[^-]+)-(?<role_hash>[a-z0-9]{10})"
| rex field=runtime_arns max_match=0 "runtime/(?<target_runtime>[A-Za-z0-9_-]+)"
| eval distinct_targets=mvcount(mvdedup(target_runtime))
| where (command="InvokeAgentRuntime" AND distinct_targets>=1) OR command IN ("ListAgentRuntimes","ListCodeInterpreters")
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Application has "Amazon Web Services" or ApplicationId == 11161
| where ActionType in ("InvokeAgentRuntime","InvokeCodeInterpreter","StartCodeInterpreterSession","ListAgentRuntimes","ListCodeInterpreters")
| extend Raw = todynamic(RawEventData)
| extend SessionRole = tostring(Raw.userIdentity.sessionContext.sessionIssuer.userName)
| where SessionRole startswith "AmazonBedrockAgentCoreSDKRuntime-"
| extend TargetRuntime = coalesce(tostring(Raw.requestParameters.agentRuntimeArn), tostring(Raw.requestParameters.codeInterpreterIdentifier), extract(@"runtime/([A-Za-z0-9_-]+)", 1, tostring(Raw.requestParameters)))
| summarize Commands=make_set(ActionType), Targets=make_set(TargetRuntime), DistinctTargets=dcount(TargetRuntime), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by SessionRole, IPAddress, AccountObjectId
| where DistinctTargets >= 1 or Commands has_any ("ListAgentRuntimes","ListCodeInterpreters")
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
