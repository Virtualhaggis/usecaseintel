# [CRIT] That AI Extension Helping You Write Emails? It’s Reading Them First

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-04-30
**Article:** https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/

## Threat Profile

Threat Research Center 
Threat Research 
Malware 
Malware 
That AI Extension Helping You Write Emails? It’s Reading Them First 
13 min read 
Related Products Advanced DNS Security Advanced URL Filtering Advanced WildFire Cloud-Delivered Security Services Prisma AIRS Prisma Browser Secure Access Service Edge (SASE) Unit 42 Incident Response 
By: Shresta Bellary Seetharam 
Nabeel Mohamed 
Billy Melicher 
Oleksii Starov 
Qinge Xie 
Fang Liu 
Published: April 30, 2026 
Categories: Malware 
Threat Re…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **IPv4 (defanged):** `158.160.66.115`
- **IPv4 (defanged):** `199.80.55.27`
- **Domain (defanged):** `mcp-browser.qubecare.ai`
- **Domain (defanged):** `api.reverserecruiting.io`
- **Domain (defanged):** `chatgptforchrome.com`
- **Domain (defanged):** `xuix.top`
- **Domain (defanged):** `newextensioninstallweb.com`
- **Domain (defanged):** `huiyiai.net`
- **Domain (defanged):** `yiban.io`
- **Domain (defanged):** `browser.cash`
- **Domain (defanged):** `banana.summarizer.one`
- **Domain (defanged):** `notionapp.cn`
- **Domain (defanged):** `vomet.ru`
- **Domain (defanged):** `pic-editor-chromeextension.uno`
- **Domain (defanged):** `gosupersonic.email`
- **SHA256:** `0cbf101e96f6d5c4146812f07105f8b89bd76dd994f540470cd1c4bc37df37d5`
- **SHA256:** `ac0a312398b3bf6b3d7c5169687ca72f361838bc5a90f2c0dbce2dc8e2094a02`
- **SHA256:** `604c7aef72892b56ac23ad54744376574239c8f0651e95dd5b6cf540eb70f7c3`
- **SHA256:** `dfe307d957724ebe32331f92d53e366b7fa85968a9564c2285c5a0142ac9e1bb`
- **SHA256:** `4e38bee33237a8c8b17a2504013e506ca7cbf667a7f68a2d94d75db505c2149f`
- **SHA256:** `c9754454efede2dec2fcb856faa40424b8df378706b664a5ae4847fcd0336b53`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1176** — Software Extensions: Browser Extensions
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1546** — Event Triggered Execution
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Unit42 GenAI extension campaign — beacon to qubecare.ai / reverserecruiting.io / browser.cash

`UC_12_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution where DNS.query IN ("mcp-browser.qubecare.ai","*.qubecare.ai","api.reverserecruiting.io","*.reverserecruiting.io","chatgptforchrome.com","*.chatgptforchrome.com","xuix.top","*.xuix.top","newextensioninstallweb.com","*.newextensioninstallweb.com","huiyiai.net","*.huiyiai.net","yiban.io","*.yiban.io","browser.cash","*.browser.cash") by DNS.query DNS.src host | `drop_dm_object_name("DNS")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.url) as url from datamodel=Web where Web.dest IN ("mcp-browser.qubecare.ai","api.reverserecruiting.io","chatgptforchrome.com","xuix.top","newextensioninstallweb.com","huiyiai.net","yiban.io","browser.cash") OR Web.url IN ("*api.reverserecruiting.io/v1/profile/sync*","*mcp-browser.qubecare.ai/chrome*") by Web.dest Web.src Web.user host | `drop_dm_object_name("Web")`]
```

**Defender KQL:**
```kql
let c2Domains = dynamic(["mcp-browser.qubecare.ai","qubecare.ai","api.reverserecruiting.io","reverserecruiting.io","chatgptforchrome.com","xuix.top","newextensioninstallweb.com","huiyiai.net","yiban.io","browser.cash"]);
let c2Ips = dynamic(["158.160.66.115","199.80.55.27"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (c2Domains)) or (RemoteIP in (c2Ips))
   or (InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","brave.exe") and RemoteUrl matches regex @"(?i)(qubecare|reverserecruiting|chatgptforchrome|xuix\.top|newextensioninstallweb|huiyiai|yiban\.io|browser\.cash)")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| union (DeviceEvents | where ActionType == "BrowserLaunchedToOpenUrl" and RemoteUrl has_any (c2Domains) | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl)
```

### [LLM] Malicious GenAI Chrome extension installed (Unit42 Apr-2026 IDs on disk)

`UC_12_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\Google\\Chrome\\User Data\\*\\Extensions\\fpeabamapgecnidibdmjoepaiehokgda\\*","*\\Google\\Chrome\\User Data\\*\\Extensions\\eebihieclccoidddmjcencomodomdoei\\*","*\\Google\\Chrome\\User Data\\*\\Extensions\\iefpkdilnfhogjbkhgnliaomoldgkdlj\\*","*\\Google\\Chrome\\User Data\\*\\Extensions\\jhhjbaicgmecddbaobeobkikgmfffaeg\\*","*/Google/Chrome/*/Extensions/fpeabamapgecnidibdmjoepaiehokgda/*","*/Google/Chrome/*/Extensions/eebihieclccoidddmjcencomodomdoei/*","*/Google/Chrome/*/Extensions/iefpkdilnfhogjbkhgnliaomoldgkdlj/*","*/Google/Chrome/*/Extensions/jhhjbaicgmecddbaobeobkikgmfffaeg/*") by host Filesystem.file_name Filesystem.process_name | `drop_dm_object_name("Filesystem")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let badExtIds = dynamic(["fpeabamapgecnidibdmjoepaiehokgda","eebihieclccoidddmjcencomodomdoei","iefpkdilnfhogjbkhgnliaomoldgkdlj","jhhjbaicgmecddbaobeobkikgmfffaeg"]);
let badHashes = dynamic(["0cbf101e96f6d5c4146812f07105f8b89bd76dd994f540470cd1c4bc37df37d5","ac0a312398b3bf6b3d7c5169687ca72f361838bc5a90f2c0dbce2dc8e2094a02","604c7aef72892b56ac23ad54744376574239c8f0651e95dd5b6cf540eb70f7c3","dfe307d957724ebe32331f92d53e366b7fa85968a9564c2285c5a0142ac9e1bb","4e38bee33237a8c8b17a2504013e506ca7cbf667a7f68a2d94d75db505c2149f","c9754454efede2dec2fcb856faa40424b8df378706b664a5ae4847fcd0336b53"]);
DeviceFileEvents
| where Timestamp > ago(60d)
| where (FolderPath has_any (badExtIds))
     or (FolderPath has "Chrome\\User Data" and FolderPath has "Extensions" and FolderPath matches regex strcat("(?i)(", strcat_array(badExtIds, "|"), ")"))
     or (SHA256 in (badHashes))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), FileCount=count() by DeviceName, InitiatingProcessAccountName, FolderPath, SHA256
```

### [LLM] AI provider API keys exfiltrated via Reverse-Recruiting custom HTTP headers

`UC_12_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_method) as methods values(Web.http_user_agent) as ua values(Web.bytes_out) as bytes_out from datamodel=Web where Web.dest="api.reverserecruiting.io" OR Web.url="*reverserecruiting.io/v1/profile/sync*" OR Web.url="*reverserecruiting.io/v1/*" by Web.src Web.user host | `drop_dm_object_name("Web")` | eval risk="AI API key + PII exfil to Reverse Recruiting C2" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe")
| where RemoteUrl has "reverserecruiting.io"
     or RemoteUrl has_any ("/v1/profile/sync","optimized-api")
| extend KeyHeaderHint = case(
    RemoteUrl has "openai", "openai-key-suspect",
    RemoteUrl has "gemini", "gemini-key-suspect",
    RemoteUrl has "claude" or RemoteUrl has "anthropic", "claude-key-suspect",
    "profile-pii")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, KeyHeaderHint
| join kind=leftouter (
    DeviceFileEvents
    | where FolderPath has "iefpkdilnfhogjbkhgnliaomoldgkdlj"
    | project DeviceName, ExtInstalled=FolderPath, ExtTime=Timestamp
  ) on DeviceName
| order by Timestamp desc
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — That AI Extension Helping You Write Emails? It’s Reading Them First

`UC_12_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — That AI Extension Helping You Write Emails? It’s Reading Them First ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("optimized-api.js","profile-sync.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("optimized-api.js","profile-sync.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — That AI Extension Helping You Write Emails? It’s Reading Them First
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("optimized-api.js", "profile-sync.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("optimized-api.js", "profile-sync.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `158.160.66.115`, `199.80.55.27`, `mcp-browser.qubecare.ai`, `api.reverserecruiting.io`, `chatgptforchrome.com`, `xuix.top`, `newextensioninstallweb.com`, `huiyiai.net` _(+7 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0cbf101e96f6d5c4146812f07105f8b89bd76dd994f540470cd1c4bc37df37d5`, `ac0a312398b3bf6b3d7c5169687ca72f361838bc5a90f2c0dbce2dc8e2094a02`, `604c7aef72892b56ac23ad54744376574239c8f0651e95dd5b6cf540eb70f7c3`, `dfe307d957724ebe32331f92d53e366b7fa85968a9564c2285c5a0142ac9e1bb`, `4e38bee33237a8c8b17a2504013e506ca7cbf667a7f68a2d94d75db505c2149f`, `c9754454efede2dec2fcb856faa40424b8df378706b664a5ae4847fcd0336b53`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
