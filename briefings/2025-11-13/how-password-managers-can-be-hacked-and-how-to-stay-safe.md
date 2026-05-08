# [CRIT] How password managers can be hacked – and how to stay safe

**Source:** ESET WeLiveSecurity
**Published:** 2025-11-13
**Article:** https://www.welivesecurity.com/en/cybersecurity/password-managers-under-attack-what-you-should-know/

## Threat Profile

The average internet user has an estimated 168 passwords for their personal accounts, according to a study from 2024 . That’s a massive 68% increase on the tally four years previously. Given the security risks associated with sharing credentials across accounts , and of using simple-to-guess passwords , most of us need help managing these logins. This is where password managers come in : enabling us to store and recall long, strong and unique passwords for each of our online accounts.
However, t…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `the1password.com`
- **Domain (defanged):** `app1password.com`
- **Domain (defanged):** `appbitwarden.com`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1056.003** — Input Capture: Web Portal Capture
- **T1555.005** — Credentials from Password Stores: Password Managers
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1102** — Web Service
- **T1567** — Exfiltration Over Web Service
- **T1071.002** — Application Layer Protocol: File Transfer Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Typosquat domains impersonating 1Password / Bitwarden (the1password.com, app1password.com, appbitwarden.com)

`UC_280_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.dest) as dest from datamodel=Web where Web.url IN ("*the1password.com*","*app1password.com*","*appbitwarden.com*") by Web.src host Web.action | `drop_dm_object_name(Web)` | append [| tstats `summariesonly` count values(Network_Traffic.dest) as dest values(Network_Traffic.app) as app from datamodel=Network_Traffic where Network_Traffic.dest IN ("*the1password.com*","*app1password.com*","*appbitwarden.com*") by Network_Traffic.src _time | `drop_dm_object_name(Network_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _PMTyposquats = dynamic(["the1password.com","app1password.com","appbitwarden.com"]);
union isfuzzy=true
    ( DeviceNetworkEvents
      | where Timestamp > ago(7d)
      | where RemoteUrl has_any (_PMTyposquats)
      | project Timestamp, Source="NetworkEvent", DeviceName, AccountName=InitiatingProcessAccountName,
                Process=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine,
                Indicator=RemoteUrl, RemoteIP ),
    ( DeviceEvents
      | where Timestamp > ago(7d)
      | where ActionType == "DnsQueryResponse"
      | extend QName = tostring(parse_json(AdditionalFields).QueryName)
      | where QName has_any (_PMTyposquats)
      | project Timestamp, Source="DnsQuery", DeviceName, AccountName=InitiatingProcessAccountName,
                Process=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine,
                Indicator=QName, RemoteIP="" ),
    ( EmailUrlInfo
      | where Timestamp > ago(7d)
      | where UrlDomain has_any (_PMTyposquats)
      | project Timestamp, Source="EmailUrl", DeviceName="", AccountName="",
                Process="", ProcessCmd="", Indicator=Url, RemoteIP="" ),
    ( UrlClickEvents
      | where Timestamp > ago(7d)
      | where Url has_any (_PMTyposquats)
      | project Timestamp, Source="UrlClick", DeviceName="", AccountName=AccountUpn,
                Process="", ProcessCmd="", Indicator=Url, RemoteIP=IPAddress )
| order by Timestamp desc
```

### [LLM] InvisibleFerret 'ssh_zcp' module reads 1Password / Dashlane extension storage

`UC_280_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where (Processes.process_name IN ("python.exe","pythonw.exe","python3.exe") OR Processes.parent_process_name IN ("python.exe","pythonw.exe","python3.exe")) AND (Processes.process IN ("*bow.py*","*pay.py*","*adc.py*","*ssh_zcp*","*aeblfdkhhhdcdjpifhhbdiojplfjncoa*","*fdjamakpfbbddfjaooikfcpapjohcfmg*","*dppgmdbiimibapkepcbdbmkaabgiofem*","*\\AppData\\Roaming\\1Password*","*\\AppData\\Roaming\\Dashlane*")) by Processes.dest Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// InvisibleFerret password-manager exfil — python interpreter touching 1Password / Dashlane stores
let _PyInterpreters = dynamic(["python.exe","pythonw.exe","python3.exe","py.exe"]);
let _IFModules     = dynamic(["bow.py","pay.py","adc.py","ssh_zcp"]);
let _PMArtefacts   = dynamic([
    @"\Local Extension Settings\aeblfdkhhhdcdjpifhhbdiojplfjncoa",   // 1Password 8 (Chrome)
    @"\Local Extension Settings\dppgmdbiimibapkepcbdbmkaabgiofem",   // 1Password (Edge)
    @"\Local Extension Settings\fdjamakpfbbddfjaooikfcpapjohcfmg",   // Dashlane (Chrome)
    @"\AppData\Roaming\1Password",
    @"\AppData\Roaming\Dashlane",
    @"\AppData\Local\1Password",
    @"\AppData\Local\Dashlane"
]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (FileName in~ (_PyInterpreters)
      or InitiatingProcessFileName in~ (_PyInterpreters))
| where ProcessCommandLine has_any (_IFModules)
      or ProcessCommandLine has_any (_PMArtefacts)
| project Timestamp, DeviceName, AccountName,
          Process       = FileName,
          ProcessCmd    = ProcessCommandLine,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd     = InitiatingProcessCommandLine,
          ParentFolder  = InitiatingProcessFolderPath,
          SHA256
| order by Timestamp desc
```

### [LLM] Python interpreter egress to api.telegram.org / DeceptiveDevelopment C2 IPs

`UC_280_8` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port values(All_Traffic.app) as app values(All_Traffic.process_name) as proc from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("python.exe","pythonw.exe","python3.exe","py.exe") AND (All_Traffic.dest IN ("api.telegram.org","95.164.17.24","185.235.241.208","147.124.214.129","23.106.253.194","147.124.214.237","67.203.7.171","45.61.131.218","135.125.248.56") OR All_Traffic.dest_port IN (21,990)) by All_Traffic.src host All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// InvisibleFerret exfil channels — python interpreter to Telegram API or DeceptiveDevelopment C2 IPs
let _PyInterpreters = dynamic(["python.exe","pythonw.exe","python3.exe","py.exe"]);
let _DDC2 = dynamic([
    "95.164.17.24","185.235.241.208","147.124.214.129","23.106.253.194",
    "147.124.214.237","67.203.7.171","45.61.131.218","135.125.248.56"
]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (_PyInterpreters)
| where InitiatingProcessAccountName !endswith "$"
| where RemoteIPType == "Public"
| where RemoteUrl has "api.telegram.org"
     or RemoteIP in (_DDC2)
     or RemotePort in (21, 990)        // FTP / FTPS — the article's other named exfil channel
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          Process=InitiatingProcessFileName,
          ProcessCmd=InitiatingProcessCommandLine,
          ProcessFolder=InitiatingProcessFolderPath,
          RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `the1password.com`, `app1password.com`, `appbitwarden.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
