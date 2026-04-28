# [CRIT] FakeWallet crypto stealer spreading through iOS apps in the App Store

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-20
**Article:** https://securelist.com/fakewallet-cryptostealer-ios-app-store/119474/

## Threat Profile

Table of Contents
Technical details 
Background 
Malicious modules for hot wallets 
The Ledger wallet malicious module 
Other distribution channels, platforms, and the SparkKitty link 
Victims 
Attribution 
Conclusion 
Indicators of compromise 
Authors
Sergey Puzan 
In March 2026, we uncovered more than twenty phishing apps in the Apple App Store masquerading as popular crypto wallets. Once launched, these apps redirect users to browser pages designed to look similar to the App Store and distrib…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `iosfc`
- **Domain (defanged):** `xxx`
- **Domain (defanged):** `www.gxzhrc`
- **Domain (defanged):** `appstoreios`
- **Domain (defanged):** `crypto-stroe`
- **Domain (defanged):** `yjzhengruol`
- **Domain (defanged):** `6688cf.jhxrpbgq`
- **Domain (defanged):** `139.180.139`
- **Domain (defanged):** `xz.apps-store`
- **Domain (defanged):** `ntm0mdkzymy3n.oukwww`
- **Domain (defanged):** `nziwytu5n.lahuafa`
- **Domain (defanged):** `zdrhnmjjndu.ulbcl`
- **Domain (defanged):** `api.npoint`
- **Domain (defanged):** `mti4ywy4.lahuafa`
- **Domain (defanged):** `mtjln.siyangoil`
- **Domain (defanged):** `odm0.siyangoil`
- **Domain (defanged):** `mgi1y.siyangoil`
- **Domain (defanged):** `mziyytm5ytk.ahroar`
- **Domain (defanged):** `ngy2yjq0otlj.ahroar`
- **Domain (defanged):** `kkkhhhnnn`
- **Domain (defanged):** `helllo2025`
- **Domain (defanged):** `sxsfcc`
- **Domain (defanged):** `nmu8n`
- **Domain (defanged):** `zmx6f`
- **Domain (defanged):** `api.dc1637`
- **MD5:** `4126348d783393dd85ede3468e48405d`
- **MD5:** `b639f7f81a8faca9c62fd227fef5e28c`
- **MD5:** `d48b580718b0e1617afc1dec028e9059`
- **MD5:** `bafba3d044a4f674fc9edc67ef6b8a6b`
- **MD5:** `79fe383f0963ae741193989c12aefacc`
- **MD5:** `8d45a67b648d2cb46292ff5041a5dd44`
- **MD5:** `7e678ca2f01dc853e85d13924e6c8a45`
- **MD5:** `be9e0d516f59ae57f5553bcc3cf296d1`
- **MD5:** `fd0dc5d4bba740c7b4cc78c4b19a5840`
- **MD5:** `7b4c61ff418f6fe80cf8adb474278311`
- **MD5:** `8cbd34393d1d54a90be3c2b53d8fc17a`
- **MD5:** `d138a63436b4dd8c5a55d184e025ef99`
- **MD5:** `5bdae6cb778d002c806bb7ed130985f3`
- **MD5:** `84c81a5e49291fe60eb9f5c1e2ac184b`
- **MD5:** `19733e0dfa804e3676f97eff90f2e467`
- **MD5:** `8f51f82393c6467f9392fb9eb46f9301`
- **MD5:** `114721fbc23ff9d188535bd736a0d30e`
- **MD5:** `686989d97cf0d70346cbde2031207cbf`
- **MD5:** `0565364633b5acdd24a498a6a9ab4eca`
- **MD5:** `417ae7f384c49de8c672aec86d5a2860`
- **MD5:** `31d25ddf2697b9e13ee883fff328b22f`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
| where FolderPath has_any ("\Ethereum\keystore\","\Bitcoin\","\Exodus\","\Electrum\wallets\","\MetaMask\","\Phantom\","\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Suspicious URL click in email — phishing landing page

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered" AND All_Email.url!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.url, All_Email.subject
| rex field=All_Email.url "https?://(?<email_domain>[^/]+)"
| join type=inner email_domain
    [| tstats `summariesonly` count
        from datamodel=Web
        where Web.action="allowed"
        by Web.src, Web.dest, Web.url, Web.user
     | rex field=Web.url "https?://(?<email_domain>[^/]+)"]
| stats values(All_Email.subject) as subject, values(Web.url) as clicked_url,
        earliest(_time) as first_seen, latest(_time) as last_seen
        by All_Email.recipient, email_domain
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let DeliveredEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTimestamp = Timestamp;
EmailUrlInfo
| where Timestamp > ago(LookbackDays)
| join kind=inner DeliveredEmails on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | project Url, ClickTimestamp = Timestamp, AccountUpn, IPAddress
  ) on Url
| project ClickTimestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, IPAddress
| order by ClickTimestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `iosfc`, `xxx`, `www.gxzhrc`, `appstoreios`, `crypto-stroe`, `yjzhengruol`, `6688cf.jhxrpbgq`, `139.180.139` _(+17 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4126348d783393dd85ede3468e48405d`, `b639f7f81a8faca9c62fd227fef5e28c`, `d48b580718b0e1617afc1dec028e9059`, `bafba3d044a4f674fc9edc67ef6b8a6b`, `79fe383f0963ae741193989c12aefacc`, `8d45a67b648d2cb46292ff5041a5dd44`, `7e678ca2f01dc853e85d13924e6c8a45`, `be9e0d516f59ae57f5553bcc3cf296d1` _(+13 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
