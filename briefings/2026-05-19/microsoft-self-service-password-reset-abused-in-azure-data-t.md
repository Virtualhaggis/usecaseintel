# [HIGH] Microsoft Self-Service Password Reset abused in Azure data theft attacks

**Source:** BleepingComputer
**Published:** 2026-05-19
**Article:** https://www.bleepingcomputer.com/news/security/microsoft-self-service-password-reset-abused-in-azure-data-theft-attacks/

## Threat Profile

Microsoft Self-Service Password Reset abused in Azure data theft attacks 
By Bill Toulas 
May 19, 2026
03:35 PM
0 
A threat actor targeting Microsoft 365 and Azure production environments is stealing data in attacks that abuse legitimate applications and administration features.
Microsoft tracks the actor as Storm-2949 and says that the purpose of the attacks is "to exfiltrate as much sensitive data from a target organization’s high-value assets as possible."
Storm-2949 used social engineering t…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `176.123.4.44`
- **IPv4 (defanged):** `91.208.197.87`
- **IPv4 (defanged):** `185.241.208.243`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1098.005** — Account Manipulation: Device Registration
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1087.004** — Account Discovery: Cloud Account
- **T1069.003** — Permission Groups Discovery: Cloud Groups
- **T1526** — Cloud Service Discovery
- **T1530** — Data from Cloud Storage
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1555.006** — Credentials from Password Stores: Cloud Secrets Management Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1562.007** — Impair Defenses: Disable or Modify Cloud Firewall
- **T1651** — Cloud Administration Command
- **T1136.003** — Create Account: Cloud Account
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Storm-2949 SSPR abuse with MFA method tampering on privileged Entra ID accounts

`UC_43_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_monitor_aad_audit` (OperationName="Reset user password" OR OperationName="Reset password (self-service)" OR OperationName="Update user") OR (Category="AuthenticationMethod" AND (OperationName="User registered security info" OR OperationName="User deleted security info" OR OperationName="Admin updated security info")) | eval target=mvindex('TargetResources{}.userPrincipalName',0) | bin _time span=30m | stats values(OperationName) as ops dc(OperationName) as op_kinds min(_time) as first max(_time) as last by target | where op_kinds>=2 AND match(mvjoin(ops,","),"(?i)reset") AND match(mvjoin(ops,","),"(?i)(security info|authentication method)") | `drop_dm_object_name("Authentication")`
```

**Defender KQL:**
```kql
let Window = 1h;
let PrivIds = IdentityInfo
| where Timestamp > ago(7d)
| where isnotempty(AssignedRoles)
| summarize by AccountObjectId;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Office 365", "Microsoft Azure", "Microsoft Entra ID")
| where ActionType in ("Reset user password.", "Reset password (self-service).", "User registered security info.", "User deleted security info.", "Admin updated security info.", "Update user.")
| extend TargetUpn = tostring(parse_json(tostring(ActivityObjects))[0].Name)
| where AccountObjectId in (PrivIds) or TargetUpn in ((PrivIds))
| summarize FirstAction=min(Timestamp), LastAction=max(Timestamp), Actions=make_set(ActionType), DistinctActionCount=dcount(ActionType), SrcIPs=make_set(IPAddress) by TargetUpn, AccountObjectId, bin(Timestamp, Window)
| where DistinctActionCount >= 2 and Actions has_any ("Reset user password.", "Reset password (self-service).") and Actions has_any ("User registered security info.", "User deleted security info.", "Admin updated security info.")
| order by FirstAction desc
```

### [LLM] High-volume Microsoft Graph directory enumeration consistent with Storm-2949 Python tooling

`UC_43_7` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`azure_monitor_aad_signin` ResourceDisplayName="Microsoft Graph" (UserAgent="*python*" OR UserAgent="*requests*" OR UserAgent="*msal*" OR UserAgent="*msgraph*" OR UserAgent="*aiohttp*" OR UserAgent="*httpx*" OR ClientAppUsed="Other clients") | bin _time span=10m | stats dc(IPAddress) as ips dc(UserAgent) as uas count by UserPrincipalName _time | where count>=200 | `drop_dm_object_name("Authentication")`
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ResourceDisplayName == "Microsoft Graph"
| where UserAgent matches regex @"(?i)python|requests|msal|msgraph|aiohttp|httpx|urllib"
   or ClientAppUsed in ("Other clients", "Unknown")
| summarize Calls=count(), DistinctIPs=dcount(IPAddress), AnyUA=any(UserAgent), AnyIP=any(IPAddress) by AccountUpn, bin(Timestamp, 10m)
| where Calls >= 200
| order by Calls desc
```

### [LLM] Storm-2949 OneDrive/SharePoint mass-download burst from compromised identity

`UC_43_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity` Workload IN ("OneDrive","SharePoint") (Operation="FileDownloaded" OR Operation="FileSyncDownloadedFull") | bin _time span=15m | stats count as files dc(SourceFileName) as distinct_files dc(Site_Url) as distinct_sites values(ClientIP) as ips by UserId _time | where files >= 200 | `drop_dm_object_name("Web")`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft OneDrive for Business", "Microsoft SharePoint Online")
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Files=count(), DistinctFiles=dcount(ObjectName), DistinctSites=dcount(tostring(parse_json(tostring(RawEventData)).SiteUrl)), SrcIPs=make_set(IPAddress), UAs=make_set(UserAgent) by AccountObjectId, AccountDisplayName, bin(Timestamp, 15m)
| where Files >= 200
| order by Files desc
```

### [LLM] Storm-2949 Azure Key Vault secret enumeration and bulk retrieval

`UC_43_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_keyvault_audit` ResourceType=VAULTS (OperationName="SecretGet" OR OperationName="SecretList" OR OperationName="VaultPut" OR OperationName="VaultPatch") | bin _time span=10m | stats dc(id_s) as secrets dc(Resource) as vaults values(OperationName) as ops values(identity_claim_upn_s) as upn values(CallerIPAddress) as ips by identity_claim_oid_g _time | where secrets>=10 OR (vaults>=2 AND mvfind(ops,"VaultP")>=0) | `drop_dm_object_name("Change")`
```

### [LLM] Storm-2949 Azure Storage account key/SAS token theft and firewall relaxation

`UC_43_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_activity` (OperationNameValue="MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION" OR OperationNameValue="MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTACCOUNTSAS/ACTION" OR OperationNameValue="MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE") | bin _time span=30m | stats values(OperationNameValue) as ops dc(_raw) as actions values(Caller) as caller values(CallerIpAddress) as ip by ResourceId _time | where mvcount(ops)>=2 AND match(mvjoin(ops,","),"LISTKEYS|LISTACCOUNTSAS") AND match(mvjoin(ops,","),"STORAGEACCOUNTS/WRITE") | `drop_dm_object_name("Change")`
```

### [LLM] Storm-2949 Azure VM Run Command and VMAccess extension abuse

`UC_43_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_activity` (OperationNameValue="MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION" OR OperationNameValue="MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE" OR (OperationNameValue="MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE" AND Properties="*VMAccess*")) | stats count by Caller CallerIpAddress ResourceId OperationNameValue _time | `drop_dm_object_name("Change")`
```

### [LLM] Storm-2949 ScreenConnect (ConnectWise Control) deployment on compromised hosts

`UC_43_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="ScreenConnect.ClientService.exe" OR Processes.process_name="ScreenConnect.WindowsClient.exe" OR Processes.process_name="ConnectWiseControl.ClientService.exe" OR (Processes.process_name="msiexec.exe" AND Processes.process="*ScreenConnect*") OR Processes.process="*ScreenConnect.ClientSetup*") by host Processes.user Processes.process_name Processes.parent_process_name _time | `drop_dm_object_name("Processes")`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ConnectWiseControl.ClientService.exe", "ScreenConnect.ClientSetup.exe")
    or ProcessCommandLine has_any ("ScreenConnect.ClientSetup", "&y=Guest&h=", "ScreenConnect.ClientService.exe install")
    or InitiatingProcessCommandLine has "ScreenConnect.ClientSetup"
| extend SuspiciousParent = iff(InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","WaAppAgent.exe","WindowsAzureGuestAgent.exe","RunCommandExtension.exe"), true, false)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SuspiciousParent, SHA256
| order by Timestamp desc
```

### [LLM] Connection from Storm-2949 known-bad infrastructure (176.123.4.44, 91.208.197.87, 185.241.208.243)

`UC_43_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("176.123.4.44","91.208.197.87","185.241.208.243") OR All_Traffic.src IN ("176.123.4.44","91.208.197.87","185.241.208.243")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port host _time | `drop_dm_object_name("All_Traffic")`
```

**Defender KQL:**
```kql
let IOCs = dynamic(["176.123.4.44", "91.208.197.87", "185.241.208.243"]);
union isfuzzy=true
  (DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in (IOCs)
    | project Timestamp, Source="DeviceNetworkEvents", DeviceName, AccountName=InitiatingProcessAccountName, RemoteIP, RemotePort, Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine),
  (AADSignInEventsBeta
    | where Timestamp > ago(30d)
    | where IPAddress in (IOCs)
    | project Timestamp, Source="AADSignInEventsBeta", DeviceName, AccountName=AccountUpn, RemoteIP=IPAddress, RemotePort=int(null), Process=Application, Cmd=UserAgent)
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `176.123.4.44`, `91.208.197.87`, `185.241.208.243`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
