# [MED] Hackers Impersonate Ghidra, dnSpy, and SpiderFoot to Spread Malware via Fake Download Sites

**Source:** Cyber Security News
**Published:** 2026-06-04
**Article:** https://cybersecuritynews.com/hackers-impersonate-ghidra-dnspy-and-spiderfoot/

## Threat Profile

Hackers are creating convincing fake websites that impersonate popular security tools to trick users into downloading malware. Instead of obvious phishing pages, these sites look almost identical to real project portals, complete with professional designs and links pointing to actual GitHub repositories. The moment a user clicks the download button, something very different happens behind [&#8230;] The post Hackers Impersonate Ghidra, dnSpy, and SpiderFoot to Spread Malware via Fake Download Sit…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `217.156.122.75`
- **IPv4 (defanged):** `94.231.205.229`
- **IPv4 (defanged):** `194.150.220.218`
- **IPv4 (defanged):** `185.161.251.58`
- **Domain (defanged):** `ghidralite.com`
- **Domain (defanged):** `dnspy.org`
- **Domain (defanged):** `ilspy.org`
- **Domain (defanged):** `appfreshstart.com`
- **Domain (defanged):** `appgetonline.com`
- **Domain (defanged):** `webinnosetup.com`
- **Domain (defanged):** `appmakingcenter.com`
- **Domain (defanged):** `yourfastcrc.com`
- **Domain (defanged):** `mobileversioncrc.com`
- **Domain (defanged):** `webcrcprove.com`
- **Domain (defanged):** `integritycrc.com`
- **Domain (defanged):** `buccstanor.pics`
- **Domain (defanged):** `baxe.pics`
- **Domain (defanged):** `intem.lat`
- **Domain (defanged):** `ropea.top`
- **Domain (defanged):** `forestoaker.com`
- **Domain (defanged):** `gluckcreek.online`
- **Domain (defanged):** `kr.hugo-lapp.co`
- **Domain (defanged):** `io.hugo-lapp.lat`
- **Domain (defanged):** `cw.hugo-lapp.lat`
- **Domain (defanged):** `st.hugo-lapp.lat`
- **Domain (defanged):** `td.hugo-lapp.lat`
- **Domain (defanged):** `fd.hugo-lapp.lat`
- **Domain (defanged):** `ed.hugo-lapp.lat`
- **Domain (defanged):** `flame-guard.cc`
- **Domain (defanged):** `carlessclapped.com`
- **Domain (defanged):** `cdn-1415.brightcanvas.digital`
- **Domain (defanged):** `originaldownloads.info`
- **Domain (defanged):** `getfluxfile.com`
- **Domain (defanged):** `oundhertobeconsist.org`
- **SHA256:** `598b023e56c45b19173e8f96c1c88036d732fec305cf6bf1b9cf4dbe304beb7f`
- **SHA256:** `74091f5a8746a1c68d73e1fc1e4e1ff514632ee3f632a8b306f35dabae2d2b64`
- **SHA256:** `15e6df0c95f2147952308e640d55270e9d097639eaebb34d4b352415f1c6bceb`
- **SHA256:** `3bb92771e287aa0a8bdd8e5b5bb697427223eaefded3d9b64b5d5c32ad40f3c2`
- **SHA256:** `cbad672d9bd06ce91ce465d049e50696fbaec9d209ca0ab1fd814d993d04bc9b`
- **SHA256:** `4cdb1f7ac502289119f7f8256f00baaa994e6ecfb4000dcf5e1c46073508fcb3`
- **SHA256:** `ce0888df5e28716432013a8ae002437bd3e993fbe8362c5ff9efbddabfe0ab77`
- **SHA256:** `26f2abfc254a59c2386dd46dca16744f7147a0f0366cb6008e1d53219175f44c`
- **SHA256:** `e6a1a428a7c09c9946f7c0179d89b263f442dc3208b5144a9146c200e4185bd6`
- **SHA256:** `87361ba2bb412dcf49f8738f3b8b9b7dccb557ad2e76ea8d98ffa5b098ae3886`
- **SHA256:** `39dc2327fe1e5a56ac5ad9dc02f0386cff3d83dcfdc558cacba42ebb9dcc5ec2`
- **SHA256:** `2e842eab0c16ddd1a2ec4a56610adb58d115b65a1e08e9b67e7e375f8eed0873`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `217.156.122.75`, `94.231.205.229`, `194.150.220.218`, `185.161.251.58`, `ghidralite.com`, `dnspy.org`, `ilspy.org`, `appfreshstart.com` _(+26 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `598b023e56c45b19173e8f96c1c88036d732fec305cf6bf1b9cf4dbe304beb7f`, `74091f5a8746a1c68d73e1fc1e4e1ff514632ee3f632a8b306f35dabae2d2b64`, `15e6df0c95f2147952308e640d55270e9d097639eaebb34d4b352415f1c6bceb`, `3bb92771e287aa0a8bdd8e5b5bb697427223eaefded3d9b64b5d5c32ad40f3c2`, `cbad672d9bd06ce91ce465d049e50696fbaec9d209ca0ab1fd814d993d04bc9b`, `4cdb1f7ac502289119f7f8256f00baaa994e6ecfb4000dcf5e1c46073508fcb3`, `ce0888df5e28716432013a8ae002437bd3e993fbe8362c5ff9efbddabfe0ab77`, `26f2abfc254a59c2386dd46dca16744f7147a0f0366cb6008e1d53219175f44c` _(+4 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
