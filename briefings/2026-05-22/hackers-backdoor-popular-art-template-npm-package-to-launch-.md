# [CRIT] Hackers Backdoor Popular art-template npm Package to Launch Watering-Hole Attacks

**Source:** Cyber Security News
**Published:** 2026-05-22
**Article:** https://cybersecuritynews.com/hackers-backdoor-popular-art-template-npm-package/

## Threat Profile

Home Cyber Security News 
Hackers Backdoor Popular art-template npm Package to Launch Watering-Hole Attacks 
By Tushar Subhra Dutta 
May 22, 2026 
A widely-used JavaScript templating library called art-template has been weaponized to deliver a sophisticated iOS browser exploit kit through a supply chain attack. 
The backdoored package silently dropped malicious code into end users’ browsers, turning everyday web applications into watering holes targeting Apple device owners worldwide.
The attack…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-23222`
- **IPv4 (defanged):** `180.178.50.158`
- **IPv4 (defanged):** `172.67.141.14`
- **IPv4 (defanged):** `104.21.40.254`
- **Domain (defanged):** `v3.jiathis.com`
- **Domain (defanged):** `utaq.cfww.shop`
- **Domain (defanged):** `cfww.shop`
- **Domain (defanged):** `l1ewsu3yjkqeroy.xyz`
- **Domain (defanged):** `git.youzzjizz.com`
- **SHA256:** `f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c`
- **SHA256:** `273206e2973df6ba7474aa66693797c98dcf26b794da4c3e863ab8d8c694868d`
- **SHA256:** `5b5fe5d92808a732d0d44246cd706295cc739ed7f4dcae19112df666bc5d4f7d`
- **SHA256:** `101afde88ff8b5c02fd341eda55022a39203088c2ff11dcb73214911cf5afb77`
- **SHA256:** `d8e3973a0b3c5359d1f53a22491b56bdd31dee13a51c01c7126bc6694584512f`
- **SHA256:** `080da430f7e3a38d7cad59887df30d9ac40e70d203c7aa5f5afaf0cafcb73e5f`
- **SHA256:** `b0b29b6148c4b0dbd77d33f821ca01e2d7a711988b854285a2606dcc53894abe`
- **SHA256:** `593548d714f6d48acb886d42bf576d8fd6b1ddae6f888dda0719671a53463663`
- **SHA256:** `2c4a5a49a84f55db0dd5554f7a9e055dbb0eae3782986726c6dcfab84ecd6dc5`
- **SHA256:** `eaab0874332777ad8a03a292bcd608a3358547f9f16ab551d34eef35d5cd539e`
- **SHA256:** `feb9442c39619d7bb3ff29de8e1d4bebceb1b24f8c0a63da2f2b30a1023dc94f`
- **SHA256:** `473f182b8cbbdb5b4b29b7ad875014d66f1691ed2e770c633b559d97243895a7`
- **SHA256:** `329ae1401819da4f87e3726b7e2707afcaf62d1219c4256c828df36af0a8784a`
- **SHA256:** `7b8436669563e7d317c219b26432bdaab70e39061ea2c1c70fcc201f2c19c470`
- **SHA256:** `de1a07d8978725eaa6da5658e373e88264ac90515750201bfbe17947d5a9e788`
- **SHA256:** `675a40df5f517f8f0cd99f74c5468f56d1d8f05003e997477a2af3bc7b0105a9`
- **SHA256:** `2cfa14b2cd1f3fd51406cf1ac49c761a5c26ce3994e97de7f1ca469d85248a52`
- **SHA256:** `ebcc76dcd5ef596e732321a8d16eb2dee525c5d9a68c700b7885648c13c65a57`
- **SHA256:** `5c0ebd86d2e8ae2087c0a4def4e0364a0cfb85c7e0a753fc96dca55b6c303432`
- **SHA1:** `8064d4e0322f069b3dba13e7957ff0ca7dab7984`
- **MD5:** `6e79ae622b7ef30f31fdbcc2dc65339e`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1105** — Ingress Tool Transfer
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1041** — Exfiltration Over C2 Channel
- **T1189** — Drive-by Compromise

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] art-template Backdoored Version Installed via Package Manager

`UC_11_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm-cli.js","yarn.exe","pnpm.exe","node.exe") (Processes.process="*art-template*4.13.3*" OR Processes.process="*art-template*4.13.5*" OR Processes.process="*art-template*4.13.6*" OR Processes.process="*art-template@4.13.3*" OR Processes.process="*art-template@4.13.5*" OR Processes.process="*art-template@4.13.6*") by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npm-cli.js")
   or InitiatingProcessFileName in~ ("npm.exe","yarn.exe","pnpm.exe")
| where ProcessCommandLine has "art-template"
| where ProcessCommandLine has_any ("4.13.3","4.13.5","4.13.6","art-template@4.13.3","art-template@4.13.5","art-template@4.13.6")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Outbound Traffic to art-template / Coruna Campaign Infrastructure

`UC_11_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("v3.jiathis.com","utaq.cfww.shop","cfww.shop","l1ewsu3yjkqeroy.xyz","git.youzzjizz.com") OR All_Traffic.dest_ip IN ("180.178.50.158","172.67.141.14","104.21.40.254")) by host All_Traffic.src All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_domains = dynamic(["v3.jiathis.com","utaq.cfww.shop","cfww.shop","l1ewsu3yjkqeroy.xyz","git.youzzjizz.com"]);
let bad_ips = dynamic(["180.178.50.158","172.67.141.14","104.21.40.254"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (isnotempty(RemoteUrl) and RemoteUrl has_any (bad_domains))
   or RemoteIP in (bad_ips)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Coruna iOS Exploit Implant File Hash Sighting (49554fde7424c31c.js)

`UC_11_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.file_name) as name values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_hash="f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c" OR Filesystem.file_hash="8064d4e0322f069b3dba13e7957ff0ca7dab7984" OR Filesystem.file_hash="6e79ae622b7ef30f31fdbcc2dc65339e" OR Filesystem.file_name="49554fde7424c31c.js") by host Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c"
   or SHA1 == "8064d4e0322f069b3dba13e7957ff0ca7dab7984"
   or MD5 == "6e79ae622b7ef30f31fdbcc2dc65339e"
   or FileName =~ "49554fde7424c31c.js"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5, FileOriginUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Coruna C2 Beacon POST to /api/ip-sync/sync

`UC_11_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.src) as src from datamodel=Web.Web where (Web.url="*l1ewsu3yjkqeroy.xyz*" OR Web.url="*/api/ip-sync/sync*") by host Web.user | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "l1ewsu3yjkqeroy.xyz" or RemoteUrl has "/api/ip-sync/sync"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] loadScript() Injection in Web Bundle Pointing to jiathis/cfww/youzzjizz

`UC_11_13` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.dest) as dest values(Web.http_referrer) as referrer from datamodel=Web.Web where (Web.url="*v3.jiathis.com/code/art.js*" OR Web.url="*v3.jiathis.com/code/jia.js*" OR Web.url="*git.youzzjizz.com/git.js*" OR Web.url="*utaq.cfww.shop/gooll/gooll.html*" OR Web.url="*utaq.cfww.shop/gooll/49554fde7424c31c.js*") by host Web.src Web.user | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (
    "v3.jiathis.com/code/art.js",
    "v3.jiathis.com/code/jia.js",
    "git.youzzjizz.com/git.js",
    "utaq.cfww.shop/gooll/gooll.html",
    "utaq.cfww.shop/gooll/49554fde7424c31c.js"
  )
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — Hackers Backdoor Popular art-template npm Package to Launch Watering-Hole Attack

`UC_11_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Backdoor Popular art-template npm Package to Launch Watering-Hole Attack ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("web.js","49554fde7424c31c.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("web.js","49554fde7424c31c.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Backdoor Popular art-template npm Package to Launch Watering-Hole Attack
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("web.js", "49554fde7424c31c.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("web.js", "49554fde7424c31c.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `180.178.50.158`, `172.67.141.14`, `104.21.40.254`, `v3.jiathis.com`, `utaq.cfww.shop`, `cfww.shop`, `l1ewsu3yjkqeroy.xyz`, `git.youzzjizz.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-23222`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c`, `273206e2973df6ba7474aa66693797c98dcf26b794da4c3e863ab8d8c694868d`, `5b5fe5d92808a732d0d44246cd706295cc739ed7f4dcae19112df666bc5d4f7d`, `101afde88ff8b5c02fd341eda55022a39203088c2ff11dcb73214911cf5afb77`, `d8e3973a0b3c5359d1f53a22491b56bdd31dee13a51c01c7126bc6694584512f`, `080da430f7e3a38d7cad59887df30d9ac40e70d203c7aa5f5afaf0cafcb73e5f`, `b0b29b6148c4b0dbd77d33f821ca01e2d7a711988b854285a2606dcc53894abe`, `593548d714f6d48acb886d42bf576d8fd6b1ddae6f888dda0719671a53463663` _(+13 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
