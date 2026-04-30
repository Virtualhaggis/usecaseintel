# [HIGH] cPanel, WHM emergency update fixes critical auth bypass bug

**Source:** BleepingComputer
**Published:** 2026-04-29
**Article:** https://www.bleepingcomputer.com/news/security/cpanel-whm-emergency-update-fixes-critical-auth-bypass-bug/

## Threat Profile

cPanel, WHM emergency update fixes critical auth bypass bug 
By Bill Toulas 
April 29, 2026
11:51 AM
0 
A critical vulnerability affecting all but the latest versions of cPanel and the WebHost Manager (WHM) dashboard could be exploited to obtain access to the control panel without authentication.
The security issue has been addressed in an emergency update that requires running a command manually to retrieve a patched version of the software.
Owned by WebPros International, WHM and cPanel are Li…

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1190** — Exploit Public-Facing Application
- **T1212** — Exploitation for Credential Access
- **T1556** — Modify Authentication Process
- **T1556.001** — Modify Authentication Process: Domain Controller Authentication
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CVE-2026-41940 cPanel/WHM auth bypass: session cache-poisoning request sequence

`UC_25_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as statuses values(Web.http_user_agent) as uas from datamodel=Web where (Web.dest_port=2087 OR Web.dest_port=2083) AND (Web.url="*/login/?*login_only=1*" OR Web.url="*/scripts2/listaccts*") by Web.src, Web.dest, Web.site | `drop_dm_object_name(Web)` | eval has_login=if(like(mvjoin(urls,"|"),"%/login/?%login_only=1%"),1,0), has_listaccts=if(like(mvjoin(urls,"|"),"%/scripts2/listaccts%") AND NOT like(mvjoin(urls,"|"),"%/cpsess%/scripts2/listaccts%"),1,0), span_sec=lastTime-firstTime | where has_login=1 AND has_listaccts=1 AND span_sec<=600 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | table firstTime lastTime src dest site span_sec methods statuses urls uas
```

**Defender KQL:**
```kql
let cpanel_ports = dynamic([2083, 2087]);
let windowStart = ago(7d);
DeviceNetworkEvents
| where Timestamp > windowStart
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (cpanel_ports) or RemotePort in (cpanel_ports)
| summarize ConnCount=count(), DistinctRemotes=dcount(RemoteIP), FirstConn=min(Timestamp), LastConn=max(Timestamp) by DeviceName, RemoteIP
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > windowStart
    | where FolderPath startswith "/var/cpanel/sessions/raw/"
    | where ActionType in ("FileCreated","FileModified")
    | summarize SessionWrites=count(), LastWrite=max(Timestamp), Writers=make_set(InitiatingProcessFileName,8) by DeviceName
) on DeviceName
| where SessionWrites >= 1 and LastWrite between (FirstConn .. (LastConn + 5m))
| project DeviceName, RemoteIP, ConnCount, SessionWrites, Writers, FirstConn, LastConn, LastWrite
| order by LastConn desc
```

### [LLM] CVE-2026-41940 CRLF-injected Authorization Basic header to cPanel/WHM (cpsrvd)

`UC_25_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`waf_or_proxy_index` (dest_port=2087 OR dest_port=2083) sourcetype IN ("haproxy:http","nginx:plus:kv","apache:access","f5:asm") ("Authorization: Basic" OR auth_basic_decoded=*) | rex field=_raw "(?i)Authorization:\s*Basic\s+(?<basic_b64>[A-Za-z0-9+/=]+)" | eval basic_decoded=if(isnotnull(basic_b64), tostring(basic_b64,"hex"), null()) | eval decoded_str=coalesce(auth_basic_decoded, _raw) | where match(decoded_str,"(?s)hasroot=1") OR match(decoded_str,"successful_internal_auth_with_timestamp=") OR match(decoded_str,"tfa_verified=1") OR match(decoded_str,"\r\n") OR match(_raw,"%0[dD]%0[aA].*hasroot") | stats count min(_time) as firstTime max(_time) as lastTime values(uri_path) as paths values(http_user_agent) as uas by src, dest, dest_port | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Linux Defender — detect cpsrvd writing CRLF-poisoned session files
let keyMarkers = dynamic(["hasroot=1","tfa_verified=1","successful_internal_auth_with_timestamp"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath startswith "/var/cpanel/sessions/raw/"
| where ActionType in ("FileCreated","FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RequestAccountName
| where InitiatingProcessFileName in~ ("cpsrvd","cpsrvd-ssl","perl")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("cpsrvd","cpsrvd-ssl")
    | project ProcTime=Timestamp, DeviceName, ProcCmd=ProcessCommandLine, ProcessId
) on DeviceName
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where ActionType == "InboundConnectionAccepted"
    | where LocalPort in (2083, 2087)
    | summarize InboundConns=count(), Sources=make_set(RemoteIP, 25), FirstInbound=min(Timestamp), LastInbound=max(Timestamp) by DeviceName
) on DeviceName
| where Timestamp between (FirstInbound .. (LastInbound + 10m))
| extend NoteworthyKeys = keyMarkers
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InboundConns, Sources, NoteworthyKeys
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
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
