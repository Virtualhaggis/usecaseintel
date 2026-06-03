# [HIGH] Multiple Cross-Site Scripting (XSS) Vulnerabilities in Mailcow

**Source:** Aikido
**Published:** 2026-04-17
**Article:** https://www.aikido.dev/blog/xss-vulnerabilities-in-mailcow

## Threat Profile

Blog Vulnerabilities & Threats Multiple Cross-Site Scripting (XSS) Vulnerabilities in Mailcow Multiple Cross-Site Scripting (XSS) Vulnerabilities in Mailcow Written by Jorian Woltjer Published on: Apr 17, 2026 Mailcow is a widely used self-hosted and open source email server that hosts everything you'd need to manage mailboxes yourself. To assess its security, we set up a local instance and ran our AI pentesting agents against it. We found three XSS vulnerabilities, including a critical vulnerab…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1566.001** — Phishing: Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mailcow Autodiscover endpoint receives unauthenticated XSS payload (GHSA-f9xf-vc72-rcgm)

`UC_348_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.http_method=POST AND Web.url="*Autodiscover.xml*" by _time, Web.src, Web.dest, Web.url, Web.http_user_agent, Web.http_referrer
| `drop_dm_object_name(Web)`
| where match(url, "(?i)(onerror|onload|<script|<img|<svg|<iframe|javascript:)") OR match(http_user_agent, "(?i)(<script|<img|onerror)")
| sort 0 - _time
```

### [LLM] Mailcow quarantine XSS via EICAR + HTML in attachment filename (GHSA-2xjc-rg88-jvpp)

`UC_348_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Email where (Email.signature="*EICAR*" OR Email.malware_signature="*EICAR*" OR Email.message_info="*EICAR*") by _time, Email.src_user, Email.recipient_address, Email.file_name, Email.subject, Email.signature
| `drop_dm_object_name(Email)`
| where match(file_name, "(?i)(<img|<script|<svg|<iframe|onerror=|onload=)")
| sort 0 - _time
```

**Defender KQL:**
```kql
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where ThreatNames has_any ("EICAR", "EICAR-Test-File", "EICAR_Test_File") or FileName has_cs "EICAR"
| where FileName has "<img" or FileName has "<script" or FileName has "<svg" or FileName has "<iframe" or FileName has "onerror=" or FileName has "onload="
| join kind=leftouter (EmailEvents | project NetworkMessageId, Subject, SenderIPv4, SenderIPv6, EmailDirection, DeliveryAction) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType, ThreatNames, MalwareFilterVerdict, SenderIPv4, EmailDirection, DeliveryAction
| order by Timestamp desc
```

### [LLM] Mailcow login with HTML/JS injected into X-Real-IP header (GHSA-jprq-w83q-q62h)

`UC_348_6` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where (Web.url="*/SOGo/*" OR Web.url="*/api/v1/*" OR Web.url="*/index.php*" OR Web.url="*mailcow*") by _time, Web.src, Web.dest, Web.url, Web.http_user_agent, Web.http_referrer
| `drop_dm_object_name(Web)`
| search ("X-Real-IP" OR "real_rip") ("<img" OR "<script" OR "<svg" OR "<iframe" OR "onerror=" OR "onload=")
| sort 0 - _time
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — Multiple Cross-Site Scripting (XSS) Vulnerabilities in Mailcow

`UC_348_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Multiple Cross-Site Scripting (XSS) Vulnerabilities in Mailcow ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("dashboard.js","quarentine.js","user.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("dashboard.js","quarentine.js","user.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Multiple Cross-Site Scripting (XSS) Vulnerabilities in Mailcow
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("dashboard.js", "quarentine.js", "user.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("dashboard.js", "quarentine.js", "user.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
