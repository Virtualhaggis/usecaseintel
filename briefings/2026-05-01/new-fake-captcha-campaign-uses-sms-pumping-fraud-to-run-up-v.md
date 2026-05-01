# [CRIT] New Fake CAPTCHA Campaign Uses SMS Pumping Fraud to Run Up Victims’ Phone Bills

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/new-fake-captcha-campaign-uses-sms-pumping/

## Threat Profile

Home Cyber Security News 
New Fake CAPTCHA Campaign Uses SMS Pumping Fraud to Run Up Victims’ Phone Bills 
By Tushar Subhra Dutta 
May 1, 2026 
A newly documented scam campaign is using fake CAPTCHA pages to silently trigger dozens of international SMS messages from victims’ mobile phones, leaving them with unexpected charges on their phone bills. 
What looks like a routine “prove you’re human” step online turns into a financial hit that many users never see coming.
CAPTCHAs have become so commo…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sweeffg.online`
- **Domain (defanged):** `colnsdital.com`
- **Domain (defanged):** `zawsterris.com`
- **Domain (defanged):** `megaplaylive.com`
- **Domain (defanged):** `ruelomamuy.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1583.008** — Acquire Infrastructure: Malvertising
- **T1566.002** — Phishing: Spearphishing Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Network connections to fake-CAPTCHA SMS-pumping (IRSF) domains (Malwarebytes-tracked)

`UC_9_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest values(DNS.answer) as answer from datamodel=Network_Resolution where DNS.query IN ("sweeffg.online","colnsdital.com","zawsterris.com","megaplaylive.com","ruelomamuy.com","*.sweeffg.online","*.colnsdital.com","*.zawsterris.com","*.megaplaylive.com","*.ruelomamuy.com") by DNS.query DNS.src host 
| `drop_dm_object_name(DNS)` 
| append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.user) as user values(Web.url) as url from datamodel=Web where Web.url IN ("*sweeffg.online*","*colnsdital.com*","*zawsterris.com*","*megaplaylive.com*","*ruelomamuy.com*") by Web.dest Web.http_referrer Web.http_user_agent | `drop_dm_object_name(Web)`] 
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let irsfDomains = dynamic(["sweeffg.online","colnsdital.com","zawsterris.com","megaplaylive.com","ruelomamuy.com"]);
let net = DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (irsfDomains)
   or tostring(parse_json(AdditionalFields).query_name) has_any (irsfDomains)
| project Timestamp, DeviceName, DeviceId, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort;
let evt = DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("DnsQueryResponse","BrowserLaunchedToOpenUrl")
| where RemoteUrl has_any (irsfDomains) or AdditionalFields has_any (irsfDomains)
| project Timestamp, DeviceName, DeviceId, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, AdditionalFields;
union net, evt
| order by Timestamp desc
```

### [LLM] Browser invoking sms: URI handler with multi-recipient pre-filled body (IRSF / Click2SMS pattern)

`UC_9_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe","safari","YourPhone.exe","PhoneExperienceHost.exe") AND (Processes.process IN ("*sms:*","*smsto:*") OR Processes.process IN ("*?body=*","*&body=*")) by Processes.dest Processes.process_name Processes.process_id host 
| `drop_dm_object_name(Processes)` 
| eval recipient_count = mvcount(split(replace(process,"^.*sms[to]*:",""),",")) 
| where recipient_count >= 3 OR match(process,"(?i)\+994|\+95|\+20|\+93|\+213|\+216|\+225|\+228|\+232|\+253|\+261|\+265|\+266") 
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let highIrsfPrefixes = dynamic(["+994","+95","+20","+93","+213","+216","+225","+228","+232","+253","+261","+265","+266","+267","+268","+269","+509"]);
let browsers = dynamic(["msedge.exe","chrome.exe","firefox.exe","brave.exe","YourPhone.exe","PhoneExperienceHost.exe","com.android.chrome","com.sec.android.app.sbrowser","mobilesafari"]);
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("BrowserLaunchedToOpenUrl","OpenProcessApiCall","AppControlPolicyApplied","ShellLinkAuditFileCreate")
| where RemoteUrl startswith "sms:" or RemoteUrl startswith "smsto:" or AdditionalFields has "sms:" or AdditionalFields has "smsto:"
| extend recipients = extract(@"^sms[to]*:([^?]+)", 1, tostring(RemoteUrl))
| extend body = extract(@"[?&]body=([^&]+)", 1, tostring(RemoteUrl))
| extend recipientCount = array_length(split(recipients, ","))
| where recipientCount >= 3 or recipients has_any (highIrsfPrefixes)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, recipients, recipientCount, body
| union (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName in~ (browsers)
    | where ProcessCommandLine has_any ("sms:","smsto:")
    | where ProcessCommandLine has "body=" or ProcessCommandLine matches regex @"sms[to]*:[+\d,]{10,}"
    | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, ProcessCommandLine, FileName, FolderPath
)
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sweeffg.online`, `colnsdital.com`, `zawsterris.com`, `megaplaylive.com`, `ruelomamuy.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
