# [CRIT] Hackers Use OrBit Rootkit to Harvest SSH and Sudo Credentials From Linux Systems

**Source:** Cyber Security News
**Published:** 2026-05-15
**Article:** https://cybersecuritynews.com/hackers-use-orbit-rootkit-to-harvest-ssh/

## Threat Profile

Home Cyber Security News 
Hackers Use OrBit Rootkit to Harvest SSH and Sudo Credentials From Linux Systems 
By Tushar Subhra Dutta 
May 15, 2026 
A dangerous rootkit called OrBit has been quietly targeting Linux systems for years, stealing login credentials and hiding deep inside infected machines without triggering most security tools. 
New research reveals that what was once believed to be a custom-built threat is actually a modified version of a publicly available rootkit, spreading across th…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `109.95.212.253`
- **IPv4 (defanged):** `109.95.211.141`
- **Domain (defanged):** `cf0.pw`
- **SHA256:** `40b5127c8cf9d6bec4dbeb61ba766a95c7b2d0cafafcb82ede5a3a679a3e3020`
- **SHA256:** `ec7462c3f4a87430eb19d16cfd775c173f4ba60d2f43697743db991c3d1c3067`
- **SHA256:** `f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8`
- **SHA256:** `d419a9b17f7b4c23fd4e80a9bce130d2a13c307fccc4bfbc4d49f6b770d06d3b`
- **SHA256:** `296d28eb7b66aa2cbea7d9c2e7dc1ad6ce6f97d44d34139760c38817aec083e7`
- **SHA256:** `3ba6c174a72e4bf5a10c8aaadab2c4b98702ee2308438e94a5512b69df998d5a`
- **SHA256:** `4203271c1a0c24443b7e85cbf066c9928fcc69934772a431d779017fb85c9d73`
- **SHA256:** `eea274eddd712fe0b4434dbef6a2a92810cb13b8be3deca0571410ee78d37c9f`
- **SHA256:** `a61386384173b352e3bd90dcef4c7268a73cd29f6ae343c15b92070b1354a349`
- **SHA256:** `a34299a16cf30dac1096c1d24188c72eed1f9d320b1585fe0de4692472e3d4dc`
- **SHA256:** `b1dd18a6a4b0c6e2589312bbec55b392a20a95824ffe630a73c94d24504c553d`
- **SHA256:** `989f7eb4f805591839bcbc321dd44418eb5694d1342e37b7f24126817f10e37e`
- **SHA256:** `8ea420d9aa341ba23cdea0ac03951bce866c933ba297268bc7db8a01ce8e9b8e`
- **SHA256:** `26082cd36fdaf76ec0d74b7fbf455418c49fbab64b20892a873c415c3bb60675`
- **SHA256:** `48a68d0555f850c36f7d338b1a42ed1a661043cacf2ba2a4b0a347fac3cb3ee6`
- **SHA256:** `fc2e0cb627a00d0e4509bd319271721ea74fb11150847213abe9e8fea060cc8a`
- **SHA256:** `8e83cbb2ed12faba9b452ea41291bcebdce08162f64ac9a5f82592df62f47613`
- **SHA256:** `2b2eeb2271c19e2097a0ef0d90b2b615c20f726590bbfee139403db1dced5b0a`
- **SHA256:** `84828f31d741f92ce4bca98cfc2148ff8cff6663e2908a025b1386dd4953ffef`
- **SHA256:** `090b15fd8912cab340b22e715d44db079ec641db5e2f92916aa1f2bc9236e03e`
- **SHA256:** `64a3ebd3ad3927fc783f6ac020d5a6192e9778fb16b51cceba06e4ee5416adff`
- **SHA256:** `b85ed15756568b85148c1d432a8920f81e4b21f2bc38f0cf51d06ced619e0e77`
- **SHA256:** `d3d204c19d93e5e37697c7f80dd0de9f76a2fb4517ced9cafd7d7d46a6e285ba`
- **SHA256:** `73b95b7d1006caf8d3477e4a9a0994eaa469e98b70b8c198a82c4a12c91ad49a`
- **SHA256:** `04c06be0f65d3ead95f3d3dd26fe150270ac8b58890e35515f9317fc7c7723c9`
- **SHA256:** `d7b487d2e840c4546661f497af0195614fc0906c03d187dc39815c811ea5ec3f`
- **SHA256:** `b982276458a85cd3dd7c8aa6cb4bbb2d4885b385053f92395a99abbfb0e43784`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1014** — Rootkit
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1056.001** — Input Capture: Keylogging
- **T1547** — Boot or Logon Autostart Execution
- **T1053.003** — Scheduled Task/Job: Cron
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] OrBit/Medusa rootkit fixed file artefacts on Linux (sshpass.txt, .logpam, .ports in /lib/lib*)

`UC_5_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/lib/libseconf/*" OR Filesystem.file_path="/lib/libntpVnQE6mk/*" OR Filesystem.file_path="/lib/locate/*" OR Filesystem.file_name="sshpass.txt" OR Filesystem.file_name=".logpam" OR Filesystem.file_name=".ports") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/lib/libseconf/"
    or FolderPath startswith "/lib/libntpVnQE6mk/"
    or FolderPath startswith "/lib/locate/"
    or FileName in~ ("sshpass.txt", ".logpam", ".ports")
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] OrBit dynamic-linker hijack — /etc/ld.so.preload modified by non-package-manager process

`UC_5_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/ld.so.preload" OR Filesystem.file_path="/etc/ld.so.conf.d/*") Filesystem.action IN ("created","modified","renamed") NOT Filesystem.process_name IN ("apt","apt-get","dpkg","rpm","yum","dnf","zypper","pacman","yast","yast2") by Filesystem.dest Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath == "/etc/" and FileName =~ "ld.so.preload"
    or FolderPath startswith "/etc/ld.so.conf.d/"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName !in~ ("apt","apt-get","dpkg","rpm","yum","dnf","zypper","pacman","yast","yast2","ldconfig")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### [LLM] OrBit cron-based payload fetch from cf0.pw / 109.95.212.253 / 109.95.211.141

`UC_5_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("109.95.212.253","109.95.211.141") OR All_Traffic.dest="cf0.pw" OR All_Traffic.url="*cf0.pw*") by All_Traffic.src All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CronArtefacts = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath == "/etc/cron.hourly/" and FileName == "0"
    | where ActionType in ("FileCreated","FileModified")
    | project CronTime = Timestamp, DeviceId, DeviceName,
              CronCreatedBy = InitiatingProcessFileName,
              CronCmd = InitiatingProcessCommandLine;
let C2Hits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP in ("109.95.212.253","109.95.211.141")
        or RemoteUrl contains "cf0.pw"
    | project NetTime = Timestamp, DeviceId, DeviceName, RemoteIP, RemoteUrl, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath;
union isfuzzy=true
    (CronArtefacts | extend Signal = "OrBit cron persistence dropped (/etc/cron.hourly/0)"),
    (C2Hits      | extend Signal = "OrBit C2 contact (cf0.pw / Russia-based IP)")
| order by coalesce(CronTime, NetTime) desc
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
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
| where AccountName !endswith "$"
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
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Article-specific behavioural hunt — Hackers Use OrBit Rootkit to Harvest SSH and Sudo Credentials From Linux Systems

`UC_5_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Use OrBit Rootkit to Harvest SSH and Sudo Credentials From Linux Systems ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/cron.hourly/0*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Use OrBit Rootkit to Harvest SSH and Sudo Credentials From Linux Systems
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/cron.hourly/0"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `109.95.212.253`, `109.95.211.141`, `cf0.pw`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `40b5127c8cf9d6bec4dbeb61ba766a95c7b2d0cafafcb82ede5a3a679a3e3020`, `ec7462c3f4a87430eb19d16cfd775c173f4ba60d2f43697743db991c3d1c3067`, `f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8`, `d419a9b17f7b4c23fd4e80a9bce130d2a13c307fccc4bfbc4d49f6b770d06d3b`, `296d28eb7b66aa2cbea7d9c2e7dc1ad6ce6f97d44d34139760c38817aec083e7`, `3ba6c174a72e4bf5a10c8aaadab2c4b98702ee2308438e94a5512b69df998d5a`, `4203271c1a0c24443b7e85cbf066c9928fcc69934772a431d779017fb85c9d73`, `eea274eddd712fe0b4434dbef6a2a92810cb13b8be3deca0571410ee78d37c9f` _(+19 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
