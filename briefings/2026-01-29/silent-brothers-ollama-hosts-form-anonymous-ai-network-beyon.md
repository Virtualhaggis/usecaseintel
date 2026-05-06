# [HIGH] Silent Brothers | Ollama Hosts Form Anonymous AI Network Beyond Platform Guardrails

**Source:** SentinelLabs
**Published:** 2026-01-29
**Article:** https://www.sentinelone.com/labs/silent-brothers-ollama-hosts-form-anonymous-ai-network-beyond-platform-guardrails/

## Threat Profile

AI Research 
Silent Brothers | Ollama Hosts Form Anonymous AI Network Beyond Platform Guardrails 
Gabriel Bernadett-Shapiro & Silas Cutler (Censys) 
/
January 29, 2026 
Executive Summary 
A joint research project between SentinelLABS and Censys reveals that open-source AI deployment has created an unmanaged, publicly accessible layer of AI compute infrastructure spanning 175,000 hosts worldwide, operating outside the guardrails and monitoring systems that platform providers implement by default.…

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
- **T1133** — External Remote Services
- **T1059** — Command and Scripting Interpreter
- **T1496** — Resource Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Local Ollama service bound to non-loopback interface (joining exposed AI network on TCP/11434)

`UC_216_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Ports where Ports.dest_port=11434 Ports.transport=tcp by Ports.dest, Ports.dest_ip, Ports.process_name, Ports.user, Ports.process_id | `drop_dm_object_name(Ports)` | where dest_ip!="127.0.0.1" AND dest_ip!="::1" AND (like(lower(process_name),"%ollama%") OR isnull(process_name)) | join type=outer dest [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="ollama*" (Processes.process="*serve*" OR Processes.process="*OLLAMA_HOST=0.0.0.0*" OR Processes.process="*OLLAMA_HOST=*:*") by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime) | table firstTime lastTime dest dest_ip user process_name process parent_process_name
```

**Defender KQL:**
```kql
// Listener-side: ollama opens TCP/11434 on a non-loopback interface
let OllamaListeners = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ListeningConnectionCreated","InboundConnectionAccepted")
| where LocalPort == 11434
| where InitiatingProcessFileName has "ollama" or InitiatingProcessFolderPath has "ollama"
| where LocalIP !in ("127.0.0.1","::1","0:0:0:0:0:0:0:1")
| project Timestamp, DeviceName, DeviceId, LocalIP, LocalPort, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName;
// Process-side: ollama serve launched with public bind via OLLAMA_HOST
let OllamaPublicServe = DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "ollama" or FileName =~ "ollama.exe" or InitiatingProcessFileName has "ollama")
| where ProcessCommandLine has "serve"
| where ProcessCommandLine has_any ("OLLAMA_HOST=0.0.0.0","OLLAMA_HOST=*",
        "--host 0.0.0.0","--host=0.0.0.0","-H 0.0.0.0")
   or InitiatingProcessCommandLine has_any ("OLLAMA_HOST=0.0.0.0","--host 0.0.0.0")
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName;
union OllamaListeners, OllamaPublicServe
| order by Timestamp desc
```

### [LLM] Endpoint outbound to public TCP/11434 — using or proxying through exposed Ollama nodes

`UC_216_4` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in dc(All_Traffic.dest_ip) as distinct_dest_ips from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=11434 All_Traffic.transport=tcp All_Traffic.action!="blocked" by All_Traffic.src, All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.app, All_Traffic.user | `drop_dm_object_name(All_Traffic)` | where !cidrmatch("10.0.0.0/8", dest_ip) AND !cidrmatch("172.16.0.0/12", dest_ip) AND !cidrmatch("192.168.0.0/16", dest_ip) AND !cidrmatch("127.0.0.0/8", dest_ip) AND !cidrmatch("169.254.0.0/16", dest_ip) AND !cidrmatch("100.64.0.0/10", dest_ip) | convert ctime(firstTime) ctime(lastTime) | sort - bytes_out
```

**Defender KQL:**
```kql
// 30-day baseline of any internal host that has previously talked to public TCP/11434
let Baseline = DeviceNetworkEvents
| where Timestamp between (ago(30d) .. ago(1d))
| where RemotePort == 11434 and RemoteIPType == "Public"
| summarize by DeviceId, RemoteIP;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 11434
| where RemoteIPType == "Public"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
| where InitiatingProcessAccountName !endswith "$"
| join kind=leftanti Baseline on DeviceId, RemoteIP        // first-time pair
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            DistinctRemoteIPs = dcount(RemoteIP),
            SampleRemoteIPs   = make_set(RemoteIP, 10),
            SampleProcesses   = make_set(InitiatingProcessFileName, 10),
            SampleCmdLines    = make_set(InitiatingProcessCommandLine, 5)
            by DeviceName, InitiatingProcessAccountName
| order by ConnCount desc
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


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
