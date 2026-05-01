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
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1496** — Resource Hijacking
- **T1090** — Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Ollama service started bound to public interface (OLLAMA_HOST=0.0.0.0 / 11434)

`UC_218_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="ollama" OR Processes.process_name="ollama.exe" OR Processes.process_name="ollama-runner" OR Processes.original_file_name="ollama") AND (Processes.process="*OLLAMA_HOST=0.0.0.0*" OR Processes.process="*OLLAMA_HOST=:11434*" OR Processes.process="*--host 0.0.0.0*" OR Processes.process="*--host=0.0.0.0*" OR Processes.process="*serve*0.0.0.0:11434*" OR Processes.process="*serve*:11434*") by Processes.dest Processes.user Processes.process_name Processes.process_id host | `drop_dm_object_name(Processes)` | `ctime(firstTime)` | `ctime(lastTime)` | eval risk_note="Ollama bound to public interface — exposed API on 11434 with no auth by default"
```

**Defender KQL:**
```kql
// UC1a: process launch with public binding
let OllamaProc = DeviceProcessEvents
| where FileName in~ ("ollama","ollama.exe","ollama-runner","ollama-runner.exe") or ProcessVersionInfoOriginalFileName =~ "ollama"
| where ProcessCommandLine has_any ("OLLAMA_HOST=0.0.0.0","OLLAMA_HOST=:11434","--host 0.0.0.0","--host=0.0.0.0","0.0.0.0:11434",":11434")
      or (ProcessCommandLine has "serve" and ProcessCommandLine has_any ("0.0.0.0",":11434"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
// UC1b: persistent env var via setx / SYSTEM env registry
let OllamaEnv = DeviceRegistryEvents
| where RegistryKey has_any (@"\Environment",@"\Session Manager\Environment")
| where RegistryValueName =~ "OLLAMA_HOST"
| where RegistryValueData has_any ("0.0.0.0",":11434") and RegistryValueData !startswith "127."
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine;
union OllamaProc, OllamaEnv
```

### [LLM] Corporate endpoint reaching out to public Ollama API (TCP/11434) — Silent Brothers abuse

`UC_218_4` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count sum(All_Traffic.bytes_out) as bytes_out sum(All_Traffic.bytes_in) as bytes_in dc(All_Traffic.dest) as dest_count values(All_Traffic.dest) as dests values(All_Traffic.app) as apps min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=11434 AND All_Traffic.transport="tcp" AND NOT (All_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","100.64.0.0/10")) AND NOT All_Traffic.dest_category="internal" by All_Traffic.src All_Traffic.user All_Traffic.src_category host | `drop_dm_object_name(All_Traffic)` | where bytes_out > 1024 OR count >= 3 | `ctime(firstTime)` | `ctime(lastTime)` | eval note="Outbound to public Ollama 11434 — likely use of unsanctioned exposed LLM endpoint" ```
``` ```appendpipe [ | tstats summariesonly=true count values(Web.url) as urls values(Web.http_method) as methods from datamodel=Web where Web.dest_port=11434 OR (Web.url="*/api/generate*" OR Web.url="*/api/chat*" OR Web.url="*/api/embeddings*" OR Web.url="*/api/tags*" OR Web.url="*/api/show*" OR Web.url="*/api/ps*") by Web.src Web.dest Web.user host | `drop_dm_object_name(Web)` | eval note="Web telemetry confirmed Ollama API call to external dest" ]
```

**Defender KQL:**
```kql
let internalRanges = dynamic(["10.","172.16.","172.17.","172.18.","172.19.","172.2","172.30.","172.31.","192.168.","127.","169.254.","100.64."]);
DeviceNetworkEvents
| where RemotePort == 11434 and Protocol =~ "Tcp"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
| where not(RemoteIP startswith_any (internalRanges))
| where ipv4_is_private(RemoteIP) == false
| summarize ConnAttempts=count(),
            BytesOutTotal=sumif(toint(InitiatingProcessFileSize),true), // placeholder – swap for proxy bytes if available
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            RemoteIPs=make_set(RemoteIP, 25),
            URLs=make_set(RemoteUrl, 25),
            Procs=make_set(InitiatingProcessFileName, 10),
            CmdLines=make_set(InitiatingProcessCommandLine, 10)
        by DeviceName, AccountName=InitiatingProcessAccountName
| where ConnAttempts >= 2
| extend Note="Internal host calling out to exposed public Ollama (11434) — possible Silent Brothers abuse / shadow-AI / exfil-via-prompt"
| order by ConnAttempts desc
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


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
