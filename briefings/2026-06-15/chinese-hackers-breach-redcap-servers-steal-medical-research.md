# [HIGH] Chinese hackers breach REDCap servers, steal medical research

**Source:** BleepingComputer
**Published:** 2026-06-15
**Article:** https://www.bleepingcomputer.com/news/security/chinese-hackers-breach-redcap-servers-steal-medical-research/

## Threat Profile

Chinese hackers breach REDCap servers, steal medical research 
By Bill Toulas 
June 15, 2026
10:00 AM
0 


A China-linked espionage campaign targeted exposed REDCap servers to deploy the InfiniteRed malware and steal sensitive data from a medical institution in North America.


Google Threat Intelligence Group (GTIG) researchers attribute the attacks to a threat actor tracked as UNC6508, who remained undetected for more than a year in the victim network.


The REDCap platform is widely use…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1114.003** — Email Forwarding Rule
- **T1567** — Exfiltration Over Web Service
- **T1098.002** — Additional Email Delegate Permissions
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1505.003** — Web Shell
- **T1554** — Compromise Host Software Binary
- **T1574.001** — DLL Search Order Hijacking
- **T1059.004** — Unix Shell
- **T1071.001** — Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exchange/Compliance content rule 'Patroit' with external Gmail BCC (UNC6508)

`UC_3_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where (All_Changes.action=created OR All_Changes.action=modified) (All_Changes.object_category="transport_rule" OR All_Changes.object_category="dlp_rule" OR All_Changes.object_category="compliance_rule") by All_Changes.user All_Changes.src All_Changes.object All_Changes.command All_Changes.result | `drop_dm_object_name(All_Changes)` | search (object="*Patroit*" OR command="*BebitaBarefoot774*" OR (command="*BlindCopyTo*" AND command="*@gmail.com*")) | rename object as RuleName, command as RuleCommand | table firstTime, lastTime, user, src, RuleName, RuleCommand
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(90d)
| where Application in~ ("Microsoft Exchange Online","Office 365 Security and Compliance","Microsoft Purview")
| where ActionType in~ ("New-TransportRule","Set-TransportRule","Enable-TransportRule","New-DlpComplianceRule","Set-DlpComplianceRule","New-DlpCompliancePolicy","Set-DlpCompliancePolicy")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("Patroit","BebitaBarefoot774")
   or (Raw has "BlindCopyTo" and Raw has "@gmail.com")
   or (Raw has "BlindCopyTo" and Raw has "@outlook.com" and Raw has "Patroit")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ActionType, ObjectName, Raw
| order by Timestamp desc
```

### Outbound mail BCC'd to UNC6508 actor dropbox BebitaBarefoot774@gmail.com

`UC_3_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subjects values(All_Email.src_user) as senders from datamodel=Email where (All_Email.recipient="BebitaBarefoot774@gmail.com" OR All_Email.message_info="*BebitaBarefoot774*") by All_Email.src_user All_Email.recipient | `drop_dm_object_name(All_Email)` | table firstTime, lastTime, src_user, recipient, subjects
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(365d)
| where RecipientEmailAddress =~ "BebitaBarefoot774@gmail.com"
   or tostring(AdditionalFields) has "BebitaBarefoot774"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, EmailDirection, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

### INFINITERED trojanization — unexpected modification of REDCap PHP system files

`UC_3_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=renamed) (Filesystem.file_path="*\\redcap\\*" OR Filesystem.file_path="*/redcap/*" OR Filesystem.file_path="*redcap_v*") Filesystem.file_name="*.php" by host Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("php.exe","composer.phar","git.exe","rsync","msiexec.exe","webdeploy.exe") | table firstTime, lastTime, host, file_path, file_name, process_name, user, hashes
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (@"\redcap\","/redcap/","redcap_v")
| where FileName endswith ".php"
| where InitiatingProcessFileName !in~ ("composer.phar","composer.exe","git.exe","rsync","msiexec.exe","webdeploy.exe","deployer.exe","tar.exe","unzip.exe")
| where InitiatingProcessAccountName !endswith "$"
| where not (InitiatingProcessFileName =~ "php.exe" and InitiatingProcessCommandLine has_any ("composer","install_redcap","upgrade_redcap"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### REDCap webserver process spawning shell / DB client — cookie-driven INFINITERED backdoor

`UC_3_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("php-fpm","php-fpm.exe","php.exe","php-cgi.exe","w3wp.exe","httpd.exe","apache2","nginx","nginx.exe") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","whoami","whoami.exe","id","net.exe","wmic.exe","mysql","mysql.exe","mysqldump","mysqldump.exe","psql","psql.exe","curl","curl.exe","wget","certutil.exe") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | table firstTime, lastTime, host, user, parent_process_name, process_name, cmdlines
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php-fpm","php-fpm.exe","php.exe","php-cgi.exe","w3wp.exe","httpd.exe","apache2","nginx","nginx.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","zsh","whoami.exe","whoami","id","net.exe","net1.exe","wmic.exe","mysql.exe","mysql","mysqldump.exe","mysqldump","psql.exe","psql","curl.exe","curl","wget.exe","wget","certutil.exe","nslookup.exe")
| where InitiatingProcessParentFileName !in~ ("systemd","supervisord","services.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
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


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
