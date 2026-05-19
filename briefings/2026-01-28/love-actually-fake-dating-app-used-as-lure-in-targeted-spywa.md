# [MED] Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-28
**Article:** https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/

## Threat Profile

ESET researchers have uncovered an Android spyware campaign leveraging romance scam tactics to target individuals in Pakistan. The campaign uses a malicious app posing as a chat platform that allows users to initiate conversations with specific “girls” – fake profiles probably operated via WhatsApp. Underneath the romance charade, the real purpose of the malicious app, which we named GhostChat, is exfiltration of the victim’s data – both upon first execution and continually while the app is inst…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1140** — Deobfuscate/Decode Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1132.001** — Data Encoding: Standard Encoding
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ClickFix-style PowerShell Base64+IEX from Run Dialog (GhostChat / PKCERT lure)

`UC_461_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powershell.exe" AND Processes.process="*FromBase64String*" AND Processes.process="*WindowStyle*" AND (Processes.process="*Invoke-Expression*" OR Processes.process="* IEX*" OR Processes.process="*|IEX*") AND Processes.parent_process_name IN ("explorer.exe","mshta.exe","cmd.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "FromBase64String"
| where ProcessCommandLine has "WindowStyle"
| where ProcessCommandLine has_any ("Invoke-Expression", " IEX", "|IEX", "iex ")
| where InitiatingProcessFileName in~ ("explorer.exe","mshta.exe","cmd.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] GhostChat C2 beacon to hitpak.org /page.php?tynor=<host>sss<user>

`UC_461_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*hitpak.org*" OR (Web.url="*page.php*" AND Web.url="*tynor=*" AND Web.url="*sss*") by Web.src Web.user Web.url Web.dest Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "hitpak.org"
   or (RemoteUrl has "/page.php" and RemoteUrl has "tynor=" and RemoteUrl has "sss")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### [LLM] GhostChat second-stage DLL download (notepad2.dll / file.dll)

`UC_461_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url IN ("*hitpak.org/notepad2.dll*","*foxy580.github.io/koko/file.dll*","*foxy580.github.io/koko/*") by Web.src Web.user Web.url Web.dest
| `drop_dm_object_name(Web)`
| appendcols [| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where Filesystem.file_hash="8B103D0AA37E5297143E21949471FD4F6B2ECBAA" OR (Filesystem.file_name IN ("notepad2.dll","file.dll") AND Filesystem.action="created") by Filesystem.dest Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`]
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any ("hitpak.org/notepad2.dll","foxy580.github.io/koko/file.dll","foxy580.github.io/koko")
  | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, Source="Network"
),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA1 =~ "8B103D0AA37E5297143E21949471FD4F6B2ECBAA"
     or (FileName in~ ("notepad2.dll","file.dll") and (FileOriginUrl has "hitpak.org" or FileOriginUrl has "foxy580.github.io"))
  | project Timestamp, DeviceName, InitiatingProcessAccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl=FileOriginUrl, RemoteIP="", Source=strcat("FileWrite:",FileName)
)
| order by Timestamp desc
```

### [LLM] PKCERT impersonation lure access (buildthenations.info)

`UC_461_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*buildthenations.info*" by Web.src Web.user Web.url Web.dest Web.http_user_agent Web.http_referrer
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| eval pkcert_flag=if(match(url,"(?i)/PKCERT/pkcert\.html"),"yes","no")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "buildthenations.info"
| extend IsPKCERTLandingPage = tostring(RemoteUrl has "/PKCERT/pkcert.html")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, IsPKCERTLandingPage
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


## Why this matters

Severity classified as **MED** based on: 6 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
