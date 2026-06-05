# [CRIT] Malicious Sicoob NuGet Steals Banking Credentials as npm Packages Target Cloud Secrets

**Source:** The Hacker News
**Published:** 2026-05-29
**Article:** https://thehackernews.com/2026/05/malicious-sicoob-nuget-steals-banking.html

## Threat Profile

Malicious Sicoob NuGet Steals Banking Credentials as npm Packages Target Cloud Secrets 
 Ravie Lakshmanan  May 29, 2026 Software Supply Chain / Threat Intelligence 
Cybersecurity researchers have discovered a malicious NuGet package that masquerades as a C# software development kit for Sicoob, one of Brazil's largest cooperative financial systems, to siphon client IDs and PFX certificates.
According to Socket , versions 2.0.0 through 2.0.4 of " Sicoob.Sdk " contain functionality to exfiltrate …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `aab.sportsontheweb.net`
- **Domain (defanged):** `oob.moika.tech`
- **SHA256:** `638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d`
- **SHA256:** `77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d`
- **SHA256:** `bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1041** — Exfiltration Over C2 Channel
- **T1102** — Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Bidirectional Communication
- **T1567.002** — Exfiltration to Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sicoob.Sdk malicious NuGet package present on developer host (v2.0.0–2.0.4)

`UC_125_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.nuget\\packages\\sicoob.sdk\\*" OR Filesystem.file_path="*\\packages\\sicoob.sdk\\*" OR Filesystem.file_path="*/.nuget/packages/sicoob.sdk/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | eval version=case(match(file_path,"(?i)sicoob\.sdk[\\/]2\.0\.[0-4]"),"malicious-2.0.0-2.0.4",1=1,"other-check") | where version="malicious-2.0.0-2.0.4" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where (FolderPath has @"\.nuget\packages\sicoob.sdk\" or FolderPath has @"\packages\sicoob.sdk\" or FolderPath has @"/.nuget/packages/sicoob.sdk/")
| extend pkgVersion = extract(@"(?i)sicoob\.sdk[\\/](\d+\.\d+\.\d+)", 1, FolderPath)
| where pkgVersion in ("2.0.0","2.0.1","2.0.2","2.0.3","2.0.4")
| where FileName endswith ".dll" or FileName endswith ".nupkg" or FileName endswith ".nuspec"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, pkgVersion, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] PFX certificate read by .NET process followed by HTTPS egress to fake-Sentry domain

`UC_125_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as pfx_time from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.pfx" OR Filesystem.file_name="*.p12") AND Filesystem.process_name IN ("dotnet.exe","w3wp.exe","csc.exe","powershell.exe","pwsh.exe") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id Filesystem.file_path | `drop_dm_object_name(Filesystem)` | rename dest as host, process_id as pid | join type=inner host pid [| tstats `summariesonly` min(_time) as net_time from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="*sportsontheweb.net" OR All_Traffic.dest_host="*moika.tech") by All_Traffic.src All_Traffic.process_id All_Traffic.dest_host | `drop_dm_object_name(All_Traffic)` | rename src as host, process_id as pid] | where net_time>=pfx_time AND (net_time-pfx_time)<=300 | eval delay_sec=net_time-pfx_time | table host user process_name pfx_time net_time delay_sec file_path dest_host
```

**Defender KQL:**
```kql
let lookback = 30d;
let maxDelay = 5m;
let PfxReads = DeviceFileEvents
| where Timestamp > ago(lookback)
| where FileName endswith ".pfx" or FileName endswith ".p12"
| where InitiatingProcessFileName in~ ("dotnet.exe","w3wp.exe","csc.exe","powershell.exe","pwsh.exe","MSBuild.exe")
| project PfxTime=Timestamp, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, PfxPath=FolderPath, PfxFile=FileName;
let Egress = DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where RemoteUrl has_any ("sportsontheweb.net","moika.tech") or RemoteIP in ("")
| project NetTime=Timestamp, DeviceId, InitiatingProcessId, RemoteUrl, RemoteIP, RemotePort;
PfxReads
| join kind=inner Egress on DeviceId, InitiatingProcessId
| where NetTime between (PfxTime .. PfxTime + maxDelay)
| extend DelaySec = datetime_diff('second', NetTime, PfxTime)
| project PfxTime, NetTime, DelaySec, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, PfxPath, PfxFile, RemoteUrl, RemoteIP, RemotePort
| order by PfxTime desc
```

### [LLM] npm install lifecycle script reads AWS/Vault/CI credentials within minutes of package install

`UC_125_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as install_time from datamodel=Endpoint.Processes where (Processes.process_name="npm.cmd" OR Processes.process_name="npm.exe" OR Processes.process_name="yarn.exe" OR Processes.process_name="pnpm.exe" OR Processes.process_name="node.exe") AND (Processes.process="*install*" OR Processes.process="*preinstall*" OR Processes.process="*postinstall*") by Processes.dest Processes.user | `drop_dm_object_name(Processes)` | rename dest as host | join type=inner host [| tstats `summariesonly` min(_time) as cred_time values(Filesystem.file_path) as cred_paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*\\.vault-token*" OR Filesystem.file_path="*/.vault-token*" OR Filesystem.file_path="*\\.npmrc*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_name=".env" OR Filesystem.file_name=".bash_history" OR Filesystem.file_name=".zsh_history") AND (Filesystem.process_name="node.exe" OR Filesystem.process_name="node" OR Filesystem.process_name="npm.exe") by Filesystem.dest | `drop_dm_object_name(Filesystem)` | rename dest as host] | where cred_time>=install_time AND (cred_time-install_time)<=600 | eval delay_sec=cred_time-install_time | table host user install_time cred_time delay_sec cred_paths
```

**Defender KQL:**
```kql
let lookback = 14d;
let maxDelay = 10m;
let Installs = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ ("npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","node.exe")
   or InitiatingProcessFileName in~ ("npm.cmd","npm.exe","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe")
| where ProcessCommandLine has_any (" install","preinstall","postinstall"," i "," ci "," add ") or InitiatingProcessCommandLine has_any (" install","preinstall","postinstall")
| project InstallTime=Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InstallCmd=ProcessCommandLine;
let CredHits = DeviceFileEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","yarn.exe","pnpm.exe")
| where (FolderPath has @"\.aws\" or FolderPath has @"/.aws/"
      or FileName in~ (".vault-token",".npmrc",".env",".bash_history",".zsh_history")
      or FolderPath has @"\.vault" or FolderPath has @"/.vault"
      or FolderPath has @"\.docker\config" or FolderPath has @"/.docker/config"
      or FolderPath has @"\.kube\config" or FolderPath has @"/.kube/config")
| project CredTime=Timestamp, DeviceId, CredPath=FolderPath, CredFile=FileName, InitiatingProcessId, InitiatingProcessCommandLine;
Installs
| join kind=inner CredHits on DeviceId
| where CredTime between (InstallTime .. InstallTime + maxDelay)
| summarize CredFilesTouched=make_set(strcat(CredPath, CredFile), 25), FirstCred=min(CredTime), LastCred=max(CredTime), Cmd=any(InstallCmd) by DeviceName, InitiatingProcessAccountName, InstallTime
| extend DelaySec = datetime_diff('second', FirstCred, InstallTime)
| order by InstallTime desc
```

### [LLM] Outbound HTTPS or DNS to Sicoob/npm-cluster exfil domains (aab.sportsontheweb.net, oob.moika.tech)

`UC_125_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.process_name) as processes values(All_Traffic.user) as users from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="aab.sportsontheweb.net" OR All_Traffic.dest_host="*.sportsontheweb.net" OR All_Traffic.dest_host="oob.moika.tech" OR All_Traffic.dest_host="*.moika.tech") by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("aab.sportsontheweb.net","sportsontheweb.net","oob.moika.tech","moika.tech")
| project Timestamp, Source="NetworkConnect", DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has_any ("sportsontheweb.net","moika.tech")
| project Timestamp, Source="DnsQuery", DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP=tostring(parse_json(AdditionalFields).IpAddress), RemotePort=int(0))
| order by Timestamp desc
```

### [LLM] Installation of vpmdhaj-published npm credential-stealer packages (14 known names)

`UC_125_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\@vpmdhaj\\devops-tools\\*" OR Filesystem.file_path="*\\node_modules\\@vpmdhaj\\elastic-helper\\*" OR Filesystem.file_path="*\\node_modules\\@vpmdhaj\\opensearch-setup\\*" OR Filesystem.file_path="*\\node_modules\\@vpmdhaj\\search-setup\\*" OR Filesystem.file_path="*\\node_modules\\app-config-utility\\*" OR Filesystem.file_path="*\\node_modules\\elastic-opensearch-helper\\*" OR Filesystem.file_path="*\\node_modules\\env-config-manager\\*" OR Filesystem.file_path="*\\node_modules\\opensearch-config-utility\\*" OR Filesystem.file_path="*\\node_modules\\opensearch-security-scanner\\*" OR Filesystem.file_path="*\\node_modules\\opensearch-setup\\*" OR Filesystem.file_path="*\\node_modules\\opensearch-setup-tool\\*" OR Filesystem.file_path="*\\node_modules\\search-cluster-setup\\*" OR Filesystem.file_path="*\\node_modules\\search-engine-setup\\*" OR Filesystem.file_path="*\\node_modules\\vpmdhaj-opensearch-setup\\*" OR Filesystem.file_path="*/node_modules/@vpmdhaj/*" OR Filesystem.file_path="*/node_modules/opensearch-setup/*" OR Filesystem.file_path="*/node_modules/opensearch-security-scanner/*" OR Filesystem.file_path="*/node_modules/env-config-manager/*") by Filesystem.dest Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MaliciousPaths = dynamic([
  @"\node_modules\@vpmdhaj\devops-tools\",
  @"\node_modules\@vpmdhaj\elastic-helper\",
  @"\node_modules\@vpmdhaj\opensearch-setup\",
  @"\node_modules\@vpmdhaj\search-setup\",
  @"\node_modules\app-config-utility\",
  @"\node_modules\elastic-opensearch-helper\",
  @"\node_modules\env-config-manager\",
  @"\node_modules\opensearch-config-utility\",
  @"\node_modules\opensearch-security-scanner\",
  @"\node_modules\opensearch-setup\",
  @"\node_modules\opensearch-setup-tool\",
  @"\node_modules\search-cluster-setup\",
  @"\node_modules\search-engine-setup\",
  @"\node_modules\vpmdhaj-opensearch-setup\",
  "/node_modules/@vpmdhaj/",
  "/node_modules/app-config-utility/",
  "/node_modules/elastic-opensearch-helper/",
  "/node_modules/env-config-manager/",
  "/node_modules/opensearch-config-utility/",
  "/node_modules/opensearch-security-scanner/",
  "/node_modules/opensearch-setup/",
  "/node_modules/opensearch-setup-tool/",
  "/node_modules/search-cluster-setup/",
  "/node_modules/search-engine-setup/",
  "/node_modules/vpmdhaj-opensearch-setup/"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (MaliciousPaths)
| where FileName in~ ("package.json","index.js","preinstall.js","postinstall.js") or FileName endswith ".tgz"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
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
  - IP / domain IOC(s): `aab.sportsontheweb.net`, `oob.moika.tech`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d`, `77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d`, `bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
