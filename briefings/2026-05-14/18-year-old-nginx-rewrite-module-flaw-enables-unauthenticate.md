# [CRIT] 18-Year-Old NGINX Rewrite Module Flaw Enables Unauthenticated RCE

**Source:** The Hacker News
**Published:** 2026-05-14
**Article:** https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html

## Threat Profile

18-Year-Old NGINX Rewrite Module Flaw Enables Unauthenticated RCE 
 Ravie Lakshmanan  May 14, 2026 Vulnerability / Web Server 
Cybersecurity researchers have disclosed multiple security vulnerabilities impacting NGINX Plus and NGINX Open, including a critical flaw that remained undetected for 18 years.
The vulnerability, discovered by depthfirst, is a heap buffer overflow issue impacting ngx_http_rewrite_module (CVE-2026-42945, CVSS v4 score: 9.2) that could allow an attacker to achieve remote…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42945`
- **CVE:** `CVE-2026-42946`
- **CVE:** `CVE-2026-40701`
- **CVE:** `CVE-2026-42934`
- **CVE:** `CVE-2026-23918`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] NGINX worker process crash burst — CVE-2026-42945 (Rift) heap overflow exploitation

`UC_40_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`nginx_error_indexes` ("worker process" AND ("exited on signal 11" OR "exited on signal 6" OR "exited on signal 7" OR "SIGSEGV" OR "SIGABRT"))
| rex "worker process (?<worker_pid>\d+) exited on signal (?<signal>\d+)"
| bin _time span=10m
| stats count AS crash_count, dc(worker_pid) AS distinct_workers, values(signal) AS signals, latest(_raw) AS sample by _time, host
| where crash_count >= 3
| eval cve="CVE-2026-42945 / 42946 / 40701 / 42934"
```

**Defender KQL:**
```kql
// MDE for Linux — repeated nginx worker spawns indicate a crash/respawn loop.
// Healthy nginx workers persist; a sustained burst of new worker PIDs on one
// host within minutes mirrors the heap-overflow exploit chain restarting workers.
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "nginx" or InitiatingProcessFileName =~ "nginx"
| where ProcessCommandLine has "worker process" or InitiatingProcessCommandLine has "master process"
| summarize WorkerSpawns = count(),
            DistinctPids = dcount(ProcessId),
            SampleCmd    = any(ProcessCommandLine),
            FirstSeen    = min(Timestamp),
            LastSeen     = max(Timestamp)
            by DeviceName, DeviceId, bin(Timestamp, 10m)
| where WorkerSpawns >= 5     // 5 = empirical: idle nginx respawns 0/10m, reload = 1-2/10m
| order by Timestamp desc
```

### [LLM] Exposure inventory — hosts running NGINX versions vulnerable to CVE-2026-42945/42946/40701/42934

`UC_40_6` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Vulnerabilities.signature) AS signatures, values(Vulnerabilities.severity) AS severity, latest(_time) AS last_seen
  FROM datamodel=Vulnerabilities
  WHERE Vulnerabilities.cve IN ("CVE-2026-42945","CVE-2026-42946","CVE-2026-40701","CVE-2026-42934")
  BY Vulnerabilities.dest, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| eval priority=case(cve="CVE-2026-42945","CRITICAL-RCE-Rift", true(),"HIGH-Worker-Restart")
| sort - count
```

**Defender KQL:**
```kql
// Direct CVE→device join. The four CVEs all come from the same F5 advisory and
// share remediation cadence, so surface them together for unified patch priority.
let TargetCVEs = dynamic(["CVE-2026-42945","CVE-2026-42946","CVE-2026-40701","CVE-2026-42934"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (TargetCVEs)
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, CvssScore, IsExploitAvailable, PublishedDate
  ) on CveId
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing, PublicIP, OSPlatform) by DeviceId
  ) on DeviceId
| project DeviceName, DeviceId, OSPlatform, IsInternetFacing, PublicIP,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, CvssScore, VulnerabilitySeverityLevel,
          IsExploitAvailable, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| extend Priority = case(
    CveId == "CVE-2026-42945" and IsInternetFacing == true, "P0-Internet-Facing-Rift",
    CveId == "CVE-2026-42945", "P1-Rift-Internal",
    IsInternetFacing == true, "P2-Internet-Facing",
    "P3-Internal")
| order by Priority asc, CvssScore desc
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
  - CVE(s): `CVE-2026-42945`, `CVE-2026-42946`, `CVE-2026-40701`, `CVE-2026-42934`, `CVE-2026-23918`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
