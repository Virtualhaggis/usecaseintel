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
- **T1213.003** — Code Repositories
- **T1530** — Data from Cloud Storage
- **T1552.007** — Container API
- **T1213** — Data from Information Repositories
- **T1565.001** — Stored Data Manipulation
- **T1548** — Abuse Elevation Control Mechanism
- **T1078.004** — Cloud Accounts
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Bedrock AgentCore execution role pulls ECR image of a different agent

`UC_160_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as repos values(All_Changes.src) as src_ip values(All_Changes.command) as commands from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.action IN ("BatchGetImage","GetDownloadUrlForLayer","GetAuthorizationToken") (All_Changes.user="*BedrockAgentCore*" OR All_Changes.user="*AgentCoreSDKRuntime*") by All_Changes.user All_Changes.action _time span=10m | `drop_dm_object_name("All_Changes")` | rex field=user "role/(?<role_name>[^/]+)" | rex field=role_name "(?<role_agent>[A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)" | mvexpand repos | rex field=repos "repository/(?<repo_name>[^/\s\"]+)" | where isnotnull(role_agent) AND isnotnull(repo_name) AND NOT match(repo_name, role_agent) | stats count min(firstTime) as firstTime max(lastTime) as lastTime values(repo_name) as cross_agent_repos values(action) as actions values(src_ip) as src_ip by role_name | where mvcount(cross_agent_repos)>=1
```

**Defender KQL:**
```kql
// Requires Microsoft Defender for Cloud Apps AWS connector — Bedrock AgentCore role pulls a non-self ECR repo
let window = 30m;
let ecr_actions = dynamic(["GetAuthorizationToken","BatchGetImage","GetDownloadUrlForLayer","BatchCheckLayerAvailability"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in (ecr_actions)
| extend RoleArn = tostring(parse_json(tostring(RawEventData)).userIdentity.arn)
| extend RoleName = tostring(extract(@"role/([^/]+)", 1, RoleArn))
| where RoleName has_any ("BedrockAgentCore","AgentCoreSDKRuntime")
| extend RoleAgentTag = tostring(extract(@"([A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)", 1, RoleName))
| extend RepoArn = tostring(parse_json(tostring(RawEventData)).requestParameters.repositoryName)
| where ActionType != "GetAuthorizationToken"  // pair the token grab with a subsequent image pull
| where isnotempty(RepoArn) and isnotempty(RoleAgentTag)
| where not(RepoArn has RoleAgentTag)
| project Timestamp, AccountDisplayName, RoleArn, RoleAgentTag, ActionType, TargetRepository = RepoArn, IPAddress, CountryCode
| order by Timestamp desc
```

### [LLM] Cross-agent Bedrock AgentCore memory access (GetMemory / RetrieveMemoryRecords)

`UC_160_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as memory_arns values(All_Changes.src) as src_ip from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.action IN ("GetMemory","RetrieveMemoryRecords","ListMemoryRecords","DeleteMemoryRecord") (All_Changes.user="*BedrockAgentCore*" OR All_Changes.user="*AgentCoreSDKRuntime*") by All_Changes.user All_Changes.action _time span=10m | `drop_dm_object_name("All_Changes")` | rex field=user "role/(?<role_name>[^/]+)" | rex field=role_name "(?<role_agent>[A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)" | mvexpand memory_arns | rex field=memory_arns "memory/(?<memory_id>[^/\s\"]+)" | rex field=memory_id "(?<memory_agent>[A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)_mem-" | where isnotnull(role_agent) AND isnotnull(memory_agent) AND role_agent!=memory_agent | stats count values(action) as actions values(memory_id) as cross_agent_memory_ids values(src_ip) as src_ip min(firstTime) as firstTime max(lastTime) as lastTime by role_name role_agent
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps AWS connector ingesting bedrock-agentcore data-plane CloudTrail events
let memory_actions = dynamic(["GetMemory","RetrieveMemoryRecords","ListMemoryRecords","DeleteMemoryRecord","PutMemoryRecord"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in (memory_actions)
| extend Raw = parse_json(tostring(RawEventData))
| extend EventSource = tostring(Raw.eventSource)
| where EventSource == "bedrock-agentcore.amazonaws.com"
| extend RoleArn = tostring(Raw.userIdentity.arn)
| extend RoleName = tostring(extract(@"role/([^/]+)", 1, RoleArn))
| where RoleName has_any ("BedrockAgentCore","AgentCoreSDKRuntime")
| extend RoleAgentTag = tostring(extract(@"([A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)", 1, RoleName))
| extend MemoryId = tostring(coalesce(Raw.requestParameters.memoryId, Raw.requestParameters.MemoryId))
| extend MemoryAgentTag = tostring(extract(@"([A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)_mem-", 1, MemoryId))
| where isnotempty(RoleAgentTag) and isnotempty(MemoryAgentTag)
| where RoleAgentTag != MemoryAgentTag
| project Timestamp, RoleArn, RoleAgentTag, ActionType, TargetMemoryId = MemoryId, MemoryAgentTag, IPAddress, CountryCode
| order by Timestamp desc
```

### [LLM] Bedrock AgentCore lateral pivot via InvokeAgentRuntime / InvokeCodeInterpreter

`UC_160_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as target_arns values(All_Changes.src) as src_ip from datamodel=Change where All_Changes.vendor_product="AWS CloudTrail" All_Changes.action IN ("InvokeAgentRuntime","InvokeCodeInterpreter","StartCodeInterpreterSession","ListCodeInterpreters","ListAgentRuntimes") (All_Changes.user="*BedrockAgentCore*" OR All_Changes.user="*AgentCoreSDKRuntime*") by All_Changes.user All_Changes.action _time span=15m | `drop_dm_object_name("All_Changes")` | rex field=user "role/(?<role_name>[^/]+)" | rex field=role_name "(?<role_agent>[A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)" | mvexpand target_arns | rex field=target_arns "(?:runtime|code-interpreter)/(?<target_id>[^/\s\"]+)" | rex field=target_id "(?<target_agent>[A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)" | where isnotnull(role_agent) AND isnotnull(target_agent) AND role_agent!=target_agent | stats count dc(target_id) as distinct_targets values(action) as actions values(target_id) as cross_agent_targets by role_name role_agent | where distinct_targets>=1
```

**Defender KQL:**
```kql
// Requires Defender for Cloud Apps AWS connector
let pivot_actions = dynamic(["InvokeAgentRuntime","InvokeCodeInterpreter","StartCodeInterpreterSession","ListCodeInterpreters","ListAgentRuntimes"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Amazon Web Services"
| where ActionType in (pivot_actions)
| extend Raw = parse_json(tostring(RawEventData))
| where tostring(Raw.eventSource) == "bedrock-agentcore.amazonaws.com"
| extend RoleArn = tostring(Raw.userIdentity.arn)
| extend RoleName = tostring(extract(@"role/([^/]+)", 1, RoleArn))
| where RoleName has_any ("BedrockAgentCore","AgentCoreSDKRuntime")
| extend RoleAgentTag = tostring(extract(@"([A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)", 1, RoleName))
| extend TargetArn = tostring(coalesce(Raw.requestParameters.agentRuntimeArn, Raw.requestParameters.codeInterpreterIdentifier, Raw.requestParameters.runtimeArn))
| extend TargetAgentTag = tostring(extract(@"([A-Za-z0-9]+_agent_[0-9]+|[A-Za-z0-9]+Agent[0-9]+)", 1, TargetArn))
| where isnotempty(RoleAgentTag) and isnotempty(TargetAgentTag)
| where RoleAgentTag != TargetAgentTag
| summarize Calls = count(), Targets = make_set(TargetArn, 25), Actions = make_set(ActionType) by RoleArn, RoleAgentTag, IPAddress, bin(Timestamp, 15m)
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
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
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
| where AccountName !endswith "$"
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
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
