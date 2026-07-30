# [CRIT] Flying Eagle Android RAT Traces Found on 170 Servers as Source Code Circulates

**Source:** The Hacker News
**Published:** 2026-07-29
**Article:** https://thehackernews.com/2026/07/flying-eagle-android-rat-traces-found.html

## Threat Profile

Flying Eagle Android RAT Traces Found on 170 Servers as Source Code Circulates 
 Swati Khandelwal  Jul 29, 2026 Mobile Security / Threat Intelligence 
Source code for the Flying Eagle Android remote access trojan (RAT) framework is circulating through criminal Telegram channels. Hunt.io and independent researcher NetAskari traced matching control panels and certificates to 170 internet servers.
They linked the framework to a fake "公安一网通办" Public Security service application targeting Android u…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `207.56.30.188`
- **IPv4 (defanged):** `207.56.30.194`
- **IPv4 (defanged):** `108.187.7.66`
- **IPv4 (defanged):** `108.187.7.71`
- **IPv4 (defanged):** `77.105.161.235`
- **IPv4 (defanged):** `154.44.25.12`
- **IPv4 (defanged):** `85.137.253.48`
- **Domain (defanged):** `110gongan.com`
- **Domain (defanged):** `fusu.us.ci`
- **Domain (defanged):** `fusu666.cc`
- **Domain (defanged):** `ls.j2x8a.top`
- **Domain (defanged):** `alcs.xyttkx.cc`
- **Domain (defanged):** `txl.xyttkx.cc`
- **Domain (defanged):** `h5.xyttkx.cc`
- **Domain (defanged):** `s.orove.cn`
- **SHA256:** `c692ad120cc90548d48dbe57d006f2403c49833b8993af3c38fe031eb39999bd`
- **SHA256:** `0376db397807c1f1e32a99a9db622f35f4fe5597bd05b4fd5e93117062e0131f`
- **SHA256:** `4395db6ad53a415532673b16f5b64207d53cecc5b15a736c038cf3890368a164`
- **SHA256:** `5dee5cde6f2874c582effe302960b21569ee007e9e0cd4f7499d418cceb9095b`
- **SHA256:** `b803cd5032dc1abd7aabc45c8cadc471c8a59872a95d48807f13e230c58230f3`
- **SHA256:** `d8a82d7b4457352774772bfac094127d7f67526ae7011d838cc3f7ccc15fd86e`
- **SHA256:** `1456f31bf6b5d4ade90fe080006478133296080353bf69c1819fa9b766e7f57a`
- **SHA256:** `773c77494d6321e4e449c9558c7915166bcb6c05e3c42a9d30e5eac4db8ee0df`
- **SHA256:** `82520e6aa6194b2de0b1c404805a5da7d3693acab8f7ae2dd5104f14baf82cd7`
- **SHA1:** `ab4224a6361e6f826fdb262276411e03f8177e30`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1437.001** — Application Layer Protocol: Web Protocols (Mobile)
- **T1660** — Phishing (Mobile)
- **T1583.004** — Acquire Infrastructure: Server

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Flying Eagle Android RAT C2 / panel infrastructure callback (confirmed IOCs)

`UC_39_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("207.56.30.188","207.56.30.194","108.187.7.66","108.187.7.71","77.105.161.235","154.44.25.12","85.137.253.48","110gongan.com","fusu.us.ci","fusu666.cc","ls.j2x8a.top","alcs.xyttkx.cc","txl.xyttkx.cc","h5.xyttkx.cc","s.orove.cn")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name("All_Traffic")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("110gongan.com","fusu.us.ci","fusu666.cc","ls.j2x8a.top","alcs.xyttkx.cc","txl.xyttkx.cc","h5.xyttkx.cc","s.orove.cn")
    or RemoteIP in ("207.56.30.188","207.56.30.194","108.187.7.66","108.187.7.71","77.105.161.235","154.44.25.12","85.137.253.48")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count(), Ports=make_set(RemotePort,10) by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by LastSeen desc
```

### Flying Eagle / SpyNote malicious APK download by hash or distribution domain

`UC_39_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("c692ad120cc90548d48dbe57d006f2403c49833b8993af3c38fe031eb39999bd","4395db6ad53a415532673b16f5b64207d53cecc5b15a736c038cf3890368a164","5dee5cde6f2874c582effe302960b21569ee007e9e0cd4f7499d418cceb9095b","b803cd5032dc1abd7aabc45c8cadc471c8a59872a95d48807f13e230c58230f3","d8a82d7b4457352774772bfac094127d7f67526ae7011d838cc3f7ccc15fd86e","1456f31bf6b5d4ade90fe080006478133296080353bf69c1819fa9b766e7f57a","773c77494d6321e4e449c9558c7915166bcb6c05e3c42a9d30e5eac4db8ee0df")) OR (Filesystem.file_name="*.apk") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name("Filesystem")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in ("c692ad120cc90548d48dbe57d006f2403c49833b8993af3c38fe031eb39999bd","4395db6ad53a415532673b16f5b64207d53cecc5b15a736c038cf3890368a164","5dee5cde6f2874c582effe302960b21569ee007e9e0cd4f7499d418cceb9095b","b803cd5032dc1abd7aabc45c8cadc471c8a59872a95d48807f13e230c58230f3","d8a82d7b4457352774772bfac094127d7f67526ae7011d838cc3f7ccc15fd86e","1456f31bf6b5d4ade90fe080006478133296080353bf69c1819fa9b766e7f57a","773c77494d6321e4e449c9558c7915166bcb6c05e3c42a9d30e5eac4db8ee0df")
    or (FileName endswith ".apk" and FileOriginUrl has_any ("110gongan.com","fusu.us.ci"))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, FileOriginUrl, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Flying Eagle / SQLRCE / Night Dragon control-panel exposed on monitored web server

`UC_39_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.uri_path="/login" (Web.uri_query="*redirect=list/basic-list*" OR Web.uri_query="*redirect=/basic*") by Web.dest Web.src Web.http_user_agent Web.status | `drop_dm_object_name("Web")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
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

### Article-specific behavioural hunt — Flying Eagle Android RAT Traces Found on 170 Servers as Source Code Circulates

`UC_39_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Flying Eagle Android RAT Traces Found on 170 Servers as Source Code Circulates ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Flying Eagle Android RAT Traces Found on 170 Servers as Source Code Circulates
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `207.56.30.188`, `207.56.30.194`, `108.187.7.66`, `108.187.7.71`, `77.105.161.235`, `154.44.25.12`, `85.137.253.48`, `110gongan.com` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c692ad120cc90548d48dbe57d006f2403c49833b8993af3c38fe031eb39999bd`, `0376db397807c1f1e32a99a9db622f35f4fe5597bd05b4fd5e93117062e0131f`, `4395db6ad53a415532673b16f5b64207d53cecc5b15a736c038cf3890368a164`, `5dee5cde6f2874c582effe302960b21569ee007e9e0cd4f7499d418cceb9095b`, `b803cd5032dc1abd7aabc45c8cadc471c8a59872a95d48807f13e230c58230f3`, `d8a82d7b4457352774772bfac094127d7f67526ae7011d838cc3f7ccc15fd86e`, `1456f31bf6b5d4ade90fe080006478133296080353bf69c1819fa9b766e7f57a`, `773c77494d6321e4e449c9558c7915166bcb6c05e3c42a9d30e5eac4db8ee0df` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
