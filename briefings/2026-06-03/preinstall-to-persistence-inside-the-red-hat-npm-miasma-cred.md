# [CRIT] Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign

**Source:** Microsoft Security Blog
**Published:** 2026-06-03
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/

## Threat Profile

Tags 
Credential theft 
npm 
Content types 
Research 
Products and services 
Microsoft Defender 
Topics 
Actionable threat insights 
Defending against advanced tactics 
Microsoft Threat Intelligence identified a large-scale npm supply chain attack affecting 32 maliciously modified packages across more than 90 versions under the @redhat-cloud-services npm scope. The compromise originated from the upstream RedHatInsights/javascript-clients Continuous Integration and Continuous Delivery (CI/CD) pip…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`
- **SHA256:** `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`
- **SHA1:** `8bf051251ec3b973e39a313547e53421a2f8d2f6`
- **SHA1:** `608d01124cd6b5b8c55888e984b4c4d9b06fa686`
- **SHA1:** `ab9903d9edc720d1e11ea7d3d3e7a1c456f44ff7`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — JavaScript
- **T1546.016** — Installer Packages
- **T1552.005** — Cloud Instance Metadata API
- **T1057** — Process Discovery
- **T1552.001** — Credentials in Files
- **T1548.003** — Sudo and Sudo Caching
- **T1098** — Account Manipulation
- **T1562.001** — Disable or Modify Tools
- **T1565.001** — Stored Data Manipulation
- **T1567.001** — Exfiltration to Code Repository
- **T1102.002** — Bidirectional Communication
- **T1080** — Taint Shared Content
- **T1098.004** — SSH Authorized Keys
- **T1485** — Data Destruction
- **T1491.001** — Internal Defacement

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Bun runtime spawned via node→shell→bun chain from npm install (Miasma dropper)

`UC_103_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="bun" OR Processes.process_name="bun.exe") AND (Processes.parent_process_name="sh" OR Processes.parent_process_name="bash" OR Processes.parent_process_name="dash" OR Processes.parent_process_name="zsh" OR Processes.parent_process_name="cmd.exe" OR Processes.parent_process_name="powershell.exe") AND (Processes.parent_process="*node*" OR Processes.parent_process="*npm*" OR Processes.parent_process="*preinstall*") by Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("bun", "bun.exe")
| where InitiatingProcessFileName in~ ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe")
| where InitiatingProcessParentFileName in~ ("node","node.exe","npm","npm-cli.js","yarn","pnpm")
   or InitiatingProcessCommandLine has_any ("preinstall","npm install","index.js")
| where FolderPath startswith "/tmp/" or FolderPath startswith "/home/runner/" or FolderPath has "/.bun/" or FolderPath has @"\AppData\Local\Temp\" or FolderPath has "/var/folders/"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
    ParentFile = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
    GrandparentFile = InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] GitHub Actions Runner.Worker process-memory secret scraping (Miasma payload)

`UC_103_13` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*Runner.Worker*" OR Processes.process="*findRunnerWorkerPIDLinux*" OR Processes.process="*\"isSecret\":true*" OR (Processes.process="*grep*" AND Processes.process="*-aoE*" AND Processes.process="*/proc/*" AND Processes.process="*cmdline*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Runner.Worker", "findRunnerWorkerPIDLinux", "\"isSecret\":true")
   or (ProcessCommandLine has "grep" and ProcessCommandLine has "-aoE" and ProcessCommandLine has "/proc/" and ProcessCommandLine has "cmdline")
   or (ProcessCommandLine has "/proc/" and ProcessCommandLine has "cmdline" and ProcessCommandLine has "tr -d")
| where InitiatingProcessFileName !in~ ("runner-worker","Runner.Listener","actions.runner")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Cloud IMDS credential harvesting from node/bun process on CI runner

`UC_103_14` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="169.254.169.254" OR All_Traffic.dest_host="metadata.google.internal") AND (All_Traffic.process_name="node" OR All_Traffic.process_name="node.exe" OR All_Traffic.process_name="bun" OR All_Traffic.process_name="bun.exe") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_host All_Traffic.process_name All_Traffic.process | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "169.254.169.254" or RemoteUrl has_any ("metadata.google.internal", "169.254.169.254", "metadata.azure.com", ".vault.azure.net")
| where InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe")
| summarize EndpointsHit = make_set(RemoteUrl), IPHits = make_set(RemoteIP), HitCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName
| where HitCount >= 1
| order by FirstSeen desc
```

### [LLM] Passwordless sudo rule dropped into /etc/sudoers.d (Miasma privilege escalation)

`UC_103_15` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*NOPASSWD:ALL*" AND (Processes.process="*/etc/sudoers.d*" OR Processes.process="*/mnt/*" OR Processes.process="*runner ALL=(ALL)*")) OR (Processes.process_name="mount" AND Processes.process="*bind*" AND Processes.process="*/etc/sudoers.d*") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "NOPASSWD:ALL"
       and ProcessCommandLine has_any ("/etc/sudoers.d","/mnt/","sudoers")
    | extend Source = "ProcessCreate"),
  (DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath startswith "/etc/sudoers.d/"
       or (FolderPath startswith "/mnt/" and FileName has_any ("runner","sudoers"))
    | where InitiatingProcessFileName in~ ("node","bun","sh","bash","dash","tee","cp","mv","dd")
    | extend Source = "FileWrite", ProcessCommandLine = InitiatingProcessCommandLine, FileName_proc = InitiatingProcessFileName)
| project Timestamp, Source, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Security vendor domain blackhole written to /etc/hosts from non-admin process

`UC_103_16` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*/etc/hosts*" AND Processes.process="*127.0.0.1*" AND (Processes.process="*>>*" OR Processes.process="*tee*" OR Processes.process_name="echo") AND (Processes.parent_process_name="node" OR Processes.parent_process_name="bun" OR Processes.parent_process_name="sh" OR Processes.parent_process_name="bash") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has "/etc/hosts"
       and ProcessCommandLine has "127.0.0.1"
       and ProcessCommandLine has_any (">>"," tee ","echo ")
    | where InitiatingProcessFileName in~ ("node","bun","sh","bash","dash","zsh","sudo")
       or InitiatingProcessParentFileName in~ ("node","bun","npm")
    | extend Source = "ProcessCreate"),
  (DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath == "/etc/" and FileName == "hosts"
    | where InitiatingProcessFileName in~ ("node","bun","sh","bash","dash","tee","sudo")
    | extend Source = "FileWrite", ProcessCommandLine = InitiatingProcessCommandLine)
| project Timestamp, Source, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Public GitHub repo creation matching Miasma 'adjective-creature-N' exfil pattern

`UC_103_17` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`github_audit_log` action="repo.create" visibility="public" (repo="*-*-*" OR description="*Miasma*" OR description="*Spreading Blight*") | rex field=repo "^(?<adj>[a-z]+)-(?<creature>[a-z]+)-(?<idx>\d{1,5})$" | where isnotnull(idx) AND idx>=0 AND idx<=99999 | stats min(_time) as firstSeen, count by user, repo, description, visibility | sort - firstSeen
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "GitHub"
| where ActionType has_any ("Create repository","RepositoryCreate","repo.create")
| extend RepoName = tostring(parse_json(RawEventData).repo)
| extend Visibility = tostring(parse_json(RawEventData).visibility)
| extend Description = tostring(parse_json(RawEventData).description)
| where Visibility =~ "public"
| where RepoName matches regex @"^[a-z]+-[a-z]+-\d{1,5}$"
   or Description has_any ("Miasma","Spreading Blight","The Spreading Blight")
   or RawEventData has "results/" and RawEventData has ".json"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, RepoName, Visibility, Description, RawEventData
| order by Timestamp desc
```

### [LLM] Worm-injected .github/setup.js commit with 'chore: update dependencies [skip ci]' message

`UC_103_18` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`github_audit_log` (action="git.push" OR action="push") (commit_message="chore: update dependencies [skip ci]" OR added_files="*.github/setup.js*") | rex max_match=1 field=added_files "(?<setupjs>\.github/setup\.js)" | where isnotnull(setupjs) OR (commit_author_email="github-actions@github.com" AND commit_message="chore: update dependencies [skip ci]") | stats min(_time) as firstSeen, dc(repo) as repoCount, values(repo) as repos by user, commit_author_email | sort - firstSeen
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "GitHub"
| where ActionType has_any ("git.push","push","PushCommit","Push")
| extend Files = tostring(parse_json(RawEventData).added)
| extend Message = tostring(parse_json(RawEventData).message)
| extend AuthorEmail = tostring(parse_json(RawEventData).author_email)
| where Files has ".github/setup.js"
   or (Message =~ "chore: update dependencies [skip ci]" and AuthorEmail =~ "github-actions@github.com")
| project Timestamp, AccountDisplayName, ObjectName, Files, Message, AuthorEmail, IPAddress, RawEventData
| order by Timestamp desc
```

### [LLM] Destructive 'rm -rf ~' or Miasma honeytoken tripwire from node/bun process tree

`UC_103_19` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="rm" AND Processes.process="*-rf*" AND (Processes.process="* ~/*" OR Processes.process="* $HOME*" OR Processes.process="*~/Documents*")) OR Processes.process="*IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner*") AND (Processes.parent_process_name="node" OR Processes.parent_process_name="bun" OR Processes.parent_process_name="sh" OR Processes.parent_process_name="bash" OR Processes.parent_process_name="npm") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("rm","rm.exe") and ProcessCommandLine has "-rf"
          and (ProcessCommandLine matches regex @"\s~/?(\s|$)"
               or ProcessCommandLine has " $HOME"
               or ProcessCommandLine has "~/Documents"
               or ProcessCommandLine matches regex @"\s/home/[^/\s]+/?(\s|$)"))
      or ProcessCommandLine has "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner"
| where InitiatingProcessFileName in~ ("node","bun","sh","bash","dash","zsh","npm")
     or InitiatingProcessParentFileName in~ ("node","bun","npm","yarn","pnpm")
     or ProcessCommandLine has "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
    InitiatingProcessParentCreationTime
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Article-specific behavioural hunt — Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing cam

`UC_103_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing cam ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js","node.js","bun.exe","npm.cmd") OR Processes.process_path="*\AppData\Local\Temp*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*\AppData\Local\Temp*" OR Filesystem.file_path="*/etc/hosts*" OR Filesystem.file_path="*/etc/sudoers.d*" OR Filesystem.file_path="*/tmp/b-*" OR Filesystem.file_path="*/tmp/p.*" OR Filesystem.file_name IN ("index.js","node.js","bun.exe","npm.cmd"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing cam
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js", "node.js", "bun.exe", "npm.cmd") or FolderPath has_any ("\AppData\Local\Temp"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("\AppData\Local\Temp", "/etc/hosts", "/etc/sudoers.d", "/tmp/b-", "/tmp/p.") or FileName in~ ("index.js", "node.js", "bun.exe", "npm.cmd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`, `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`, `8bf051251ec3b973e39a313547e53421a2f8d2f6`, `608d01124cd6b5b8c55888e984b4c4d9b06fa686`, `ab9903d9edc720d1e11ea7d3d3e7a1c456f44ff7`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 20 use case(s) fired, 32 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
