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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GhostChat C2 beacon to hitpak.org with 'tynor=<host>sss<user>' URI pattern

`UC_223_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as ua values(Web.dest) as dest values(Web.dest_ip) as dest_ip from datamodel=Web where Web.url="*hitpak.org/page.php*" OR Web.url="*tynor=*sss*" OR Web.dest="hitpak.org" by Web.src, Web.user | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "hitpak.org" or RemoteIP == "188.114.96.10" or RemoteUrl matches regex @"tynor=[^&]+sss[^&]+"
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
| join kind=leftouter (DeviceProcessEvents | where ProcessCommandLine has_any ("FromBase64String","Invoke-Expression","notepad2.dll","file.dll") | project DeviceId, ProcCmd=ProcessCommandLine, ProcTime=Timestamp) on DeviceId
```

### [LLM] GhostChat second-stage DLL fetch from foxy580.github.io/koko or hitpak.org/notepad2.dll

`UC_223_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_user_agent) as ua from datamodel=Web where (Web.url="*foxy580.github.io/koko/file.dll*" OR Web.url="*hitpak.org/notepad2.dll*" OR (Web.url="*foxy580.github.io*" AND Web.url="*koko*")) by Web.src, Web.user, Web.dest | `drop_dm_object_name(Web)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="file.dll" OR Filesystem.file_name="notepad2.dll") AND (Filesystem.file_hash="8B103D0AA37E5297143E21949471FD4F6B2ECBAA") by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let urls = dynamic(["foxy580.github.io/koko/file.dll","hitpak.org/notepad2.dll"]);
let sha1s = dynamic(["8B103D0AA37E5297143E21949471FD4F6B2ECBAA","B15B1F3F2227EBA4B69C85BDB638DF34B9D30B6A"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (urls) or (RemoteUrl has "foxy580.github.io" and RemoteUrl has "koko")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| union (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("file.dll","notepad2.dll") or SHA1 in (sha1s)
    | project Timestamp, DeviceName, DeviceId, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine)
```

### [LLM] Visit to fake PKCERT lure on buildthenations.info preceding scripted execution

`UC_223_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as lure_url from datamodel=Web where Web.url="*buildthenations.info*" OR Web.url="*PKCERT/pkcert.html*" by Web.src Web.user | `drop_dm_object_name(Web)` | join type=inner src [| tstats `summariesonly` count values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name=powershell.exe OR Processes.process_name=mshta.exe) AND (Processes.process="*FromBase64String*" OR Processes.process="*tynor=*" OR Processes.process="*hitpak.org*" OR Processes.process="*foxy580.github.io*") by Processes.dest Processes.user | rename Processes.dest as src Processes.user as user | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let lureHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "buildthenations.info" or RemoteUrl has "PKCERT/pkcert.html"
    | project lureTime=Timestamp, DeviceId, DeviceName, lureUrl=RemoteUrl;
let badProcs = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe") or FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
    | where ProcessCommandLine has_any ("hitpak.org","foxy580.github.io","notepad2.dll","tynor=")
        or (ProcessCommandLine has "FromBase64String" and ProcessCommandLine has "Invoke-Expression" and ProcessCommandLine has "WindowStyle Hidden")
    | project procTime=Timestamp, DeviceId, DeviceName, ProcessCommandLine, FileName, InitiatingProcessFileName;
lureHits
| join kind=inner badProcs on DeviceId
| where procTime between (lureTime .. lureTime + 1h)
| project lureTime, procTime, DeviceName, lureUrl, FileName, InitiatingProcessFileName, ProcessCommandLine
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

Severity classified as **MED** based on: 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
