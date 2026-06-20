# [HIGH] Threat Brief: Mitigating Large-Scale Credential Attacks

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-06-20
**Article:** https://unit42.paloaltonetworks.com/large-scale-credential-attacks/

## Threat Profile

Threat Research Center 
High Profile Threats 
General 
General 
Threat Brief: Mitigating Large-Scale Credential Attacks 
4 min read 
Related Products Next-Generation Firewall Unit 42 Incident Response 
By: Andy Piazza 
Published: June 19, 2026 
Categories: General 
High Profile Threats 
Tags: Credential theft 
Fortibleed 
Password spraying 
Unit 42 is aware of a large-scale password spraying and credential theft campaign (“FortiBleed”) against Fortinet devices. We observed attempts targeting MSS…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-55591`
- **CVE:** `CVE-2025-59718`
- **CVE:** `CVE-2025-59719`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1110.003** — Password Spraying
- **T1133** — External Remote Services
- **T1078.003** — Valid Accounts: Local Accounts
- **T1602.002** — Data from Configuration Repository: Network Device Configuration Dump
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FortiBleed: Password spray against internet-exposed Fortinet/Sophos edge services

`UC_1_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=failure (Authentication.app IN ("fortinet","fortigate","fortios","sslvpn","ssl_vpn","sophos","sfos","xg_firewall") OR Authentication.vendor IN ("Fortinet","Sophos")) by _time span=10m Authentication.src Authentication.user Authentication.dest Authentication.app Authentication.vendor
| `drop_dm_object_name(Authentication)`
| stats dc(user) as distinct_users count as failures values(user) as user_sample values(dest) as appliance_sample by src, vendor, app, _time
| where distinct_users >= 8
| eval description="FortiBleed spray pattern: ".distinct_users." distinct users from ".src." against ".vendor." appliance(s) in 10m"
| sort - _time
```

**Defender KQL:**
```kql
let SprayWindowMin = 10m;
let SprayUserThreshold = 8;
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| where Protocol in~ ("Ntlm","Kerberos","Radius","Ldap")
| where isnotempty(IPAddress)
| where AccountName !endswith "$" and AccountName !in~ ("system","local service","network service")
| summarize FailureCount = count(),
            DistinctUsers = dcount(AccountUpn),
            UserSample = make_set(AccountName, 10),
            FirstFailure = min(Timestamp),
            LastFailure = max(Timestamp),
            ImpactedDCs = make_set(DestinationDeviceName, 5)
        by IPAddress, bin(Timestamp, SprayWindowMin)
| where DistinctUsers >= SprayUserThreshold
| order by FirstFailure desc
```

### FortiBleed: MSSQL credential spray from external source

`UC_1_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=failure (Authentication.app IN ("mssql","mssqlserver","sqlserver") OR Authentication.dest_category="database_server" OR Authentication.signature_id IN ("18456","4625") OR Authentication.process_name="sqlservr.exe") by _time span=10m Authentication.src Authentication.user Authentication.dest
| `drop_dm_object_name(Authentication)`
| stats dc(user) as distinct_users count as failures values(user) as users values(dest) as servers by src, _time
| where distinct_users >= 8
| eval description="MSSQL spray: ".distinct_users." distinct logins from ".src." in 10m"
| sort - _time
```

**Defender KQL:**
```kql
let SprayWindowMin = 10m;
let SprayUserThreshold = 8;
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| where InitiatingProcessFileName has_any ("sqlservr.exe","sqlbrowser.exe")
      or AccountName has_any ("sa","sqlservice","mssql","sqluser","sqladmin","sql_svc","dbadmin")
| where LogonType in~ ("Network","NetworkClearText","NetworkCleartext","Service")
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| where AccountName !endswith "$"
| summarize FailureCount = count(),
            DistinctUsers = dcount(AccountName),
            UserSample = make_set(AccountName, 10),
            FirstFailure = min(Timestamp),
            LastFailure = max(Timestamp),
            ImpactedHosts = make_set(DeviceName, 5)
        by RemoteIP, bin(Timestamp, SprayWindowMin)
| where DistinctUsers >= SprayUserThreshold
| order by FirstFailure desc
```

### FortiBleed: Edge appliance successful login shortly after failed-login burst from same SourceIP

`UC_1_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where (Authentication.app IN ("fortinet","fortigate","fortios","sslvpn","sophos","sfos") OR Authentication.vendor IN ("Fortinet","Sophos")) Authentication.action=failure by _time span=10m Authentication.src Authentication.dest Authentication.user
| `drop_dm_object_name(Authentication)`
| stats dc(user) as burst_distinct_users count as burst_failures values(user) as burst_users min(_time) as burst_start max(_time) as burst_end by src, dest
| where burst_failures >= 5
| join type=inner src dest [
    | tstats `summariesonly` count from datamodel=Authentication where (Authentication.app IN ("fortinet","fortigate","fortios","sslvpn","sophos","sfos") OR Authentication.vendor IN ("Fortinet","Sophos")) Authentication.action=success by _time span=10m Authentication.src Authentication.dest Authentication.user
    | `drop_dm_object_name(Authentication)`
    | rename _time as success_time, user as success_user
  ]
| where success_time >= burst_start AND success_time <= burst_end + 600
| eval delay_sec = success_time - burst_end
| table burst_start burst_end success_time delay_sec src dest success_user burst_failures burst_distinct_users
| sort - success_time
```

**Defender KQL:**
```kql
let LookbackHours = 24h;
let BurstFailureThreshold = 5;
let BurstUserThreshold = 3;
let AfterBurstWindow = 10m;
let Failures = IdentityLogonEvents
    | where Timestamp > ago(LookbackHours)
    | where ActionType == "LogonFailed"
    | where Protocol in~ ("Radius","Ntlm","Kerberos","Ldap")
    | where AccountName !endswith "$";
let Successes = IdentityLogonEvents
    | where Timestamp > ago(LookbackHours)
    | where ActionType == "LogonSuccess"
    | where Protocol in~ ("Radius","Ntlm","Kerberos","Ldap");
let Bursts = Failures
    | summarize BurstFailures = count(),
                BurstDistinctUsers = dcount(AccountUpn),
                BurstStart = min(Timestamp),
                BurstEnd = max(Timestamp)
            by IPAddress, DestinationDeviceName
    | where BurstFailures >= BurstFailureThreshold and BurstDistinctUsers >= BurstUserThreshold;
Bursts
| join kind=inner (
    Successes
    | project SuccessTime = Timestamp, SuccessIP = IPAddress, SuccessHost = DestinationDeviceName,
              SuccessUser = AccountUpn, SuccessAccount = AccountName
  ) on $left.IPAddress == $right.SuccessIP, $left.DestinationDeviceName == $right.SuccessHost
| where SuccessTime between (BurstStart .. BurstEnd + AfterBurstWindow)
| extend DelaySec = datetime_diff('second', SuccessTime, BurstEnd)
| project BurstStart, BurstEnd, SuccessTime, DelaySec,
          SourceIP = IPAddress, ApplianceOrDC = DestinationDeviceName,
          BurstFailures, BurstDistinctUsers, SuccessUser, SuccessAccount
| order by SuccessTime desc
```

### FortiOS device configuration export ('execute backup config') by non-baselined admin

`UC_1_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Change where (Change.vendor_product IN ("Fortinet*","FortiGate*","FortiOS*")) (Change.command IN ("execute backup config*","execute backup full-config*","execute backup config flash*","execute backup config tftp*","execute backup config ftp*","execute backup config scp*") OR Change.change_type IN ("config_backup","config_export")) by _time Change.user Change.src Change.dest Change.command Change.result
| `drop_dm_object_name(Change)`
| stats values(command) as commands, values(src) as source_ips, values(result) as results, count by _time, user, dest
| sort - _time
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-55591`, `CVE-2025-59718`, `CVE-2025-59719`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
