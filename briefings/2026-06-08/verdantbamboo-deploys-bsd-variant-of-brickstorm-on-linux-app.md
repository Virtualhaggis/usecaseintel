# [CRIT] VerdantBamboo Deploys BSD Variant of BRICKSTORM on Linux Appliances

**Source:** The Hacker News
**Published:** 2026-06-08
**Article:** https://thehackernews.com/2026/06/verdantbamboo-deploys-bsd-variant-of.html

## Threat Profile

VerdantBamboo Deploys BSD Variant of BRICKSTORM on Linux Appliances 
 Ravie Lakshmanan  Jun 08, 2026 Cyber Espionage / Malware 
A China-nexus cyber espionage group has been observed deploying a BSD variant of a known backdoor called BRICKSTORM, as well as two other malware families codenamed PLENET (aka GRIMBOLT ) and AGENTPSD to target Linux systems.
The activity has been attributed by Volexity to a threat cluster it tracks as VerdantBamboo , which it said overlaps with hacking groups known a…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-22769`
- **IPv4 (defanged):** `149.248.11.71`
- **SHA256:** `ee41e06ed96182ce80cd4544a6abd5d7719c4a5c0e5ddb266a83842d39b99b0a`
- **SHA256:** `40d264cf9c73923932c3dfd52d20f46ff602be3fea8dc6ecc71aca46e6067bf5`
- **SHA256:** `f70abe93121637d3ec2f6c5e058ccac0307ebf63e496f38588cbfc17a8f8a264`
- **SHA256:** `eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e`
- **SHA256:** `24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c`
- **SHA256:** `dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591`
- **SHA256:** `92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a`
- **SHA256:** `aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878`
- **SHA256:** `2388ed7aee0b6b392778e8f9e98871c06499f476c9e7eae6ca0916f827fe65df`
- **SHA256:** `320a0b5d4900697e125cebb5ff03dee7368f8f087db1c1570b0b62f5a986d759`
- **SHA256:** `90b760ed1d0dcb3ef0f2b6d6195c9d852bcb65eca293578982a8c4b64f51b035`
- **SHA256:** `45313a6745803a7f57ff35f5397fdf117eaec008a76417e6e2ac8a6280f7d830`
- **SHA1:** `e952c18272efa1c3d73d0a5381bcf443c02743fe`
- **SHA1:** `f4d77958a12a0778283d3e679b24b18f82e332c4`
- **SHA1:** `681075027553546c119ec447eb8df84633dcffce`
- **SHA1:** `f8d93c1769e877aae7e7d5c289a467b5ae371c7a`
- **MD5:** `98ee964edeb5a988c3bba8ea1e57fe0e`
- **MD5:** `58d4eccc982c9e9b1b98aa62c514e53a`
- **MD5:** `84ad78b2bab946c3677fdc28ebd8a774`
- **MD5:** `95dc2289427ed29b8b996d0e3d1b78cb`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1090.002** — Proxy: External Proxy
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1505.003** — Server Software Component: Web Shell
- **T1090** — Proxy
- **T1021.004** — Remote Services: SSH
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1556** — Modify Authentication Process
- **T1133** — External Remote Services
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### M365 / Entra sign-ins sourced from BRICKSTORM C2 IP 149.248.11.71

`UC_72_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as user values(Authentication.app) as app values(Authentication.user_agent) as user_agent from datamodel=Authentication where Authentication.src="149.248.11.71" by Authentication.dest Authentication.signature Authentication.action | `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress == "149.248.11.71"
| project Timestamp, AccountUpn, AccountDisplayName, IPAddress, Application, ApplicationId, ResourceDisplayName, ClientAppUsed, UserAgent, ConditionalAccessStatus, RiskLevelDuringSignIn, ErrorCode, Country
| order by Timestamp desc
```

### VerdantBamboo BRICKSTORM / PLENET / AGENTPSD file-hash IOCs

`UC_72_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("ee41e06ed96182ce80cd4544a6abd5d7719c4a5c0e5ddb266a83842d39b99b0a","40d264cf9c73923932c3dfd52d20f46ff602be3fea8dc6ecc71aca46e6067bf5","f70abe93121637d3ec2f6c5e058ccac0307ebf63e496f38588cbfc17a8f8a264","eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e","24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c","dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591","92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a","aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878","e952c18272efa1c3d73d0a5381bcf443c02743fe","f4d77958a12a0778283d3e679b24b18f82e332c4","681075027553546c119ec447eb8df84633dcffce","f8d93c1769e877aae7e7d5c289a467b5ae371c7a","98ee964edeb5a988c3bba8ea1e57fe0e","58d4eccc982c9e9b1b98aa62c514e53a","84ad78b2bab946c3677fdc28ebd8a774","95dc2289427ed29b8b996d0e3d1b78cb") by Processes.dest Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let SHA256s = dynamic(["ee41e06ed96182ce80cd4544a6abd5d7719c4a5c0e5ddb266a83842d39b99b0a","40d264cf9c73923932c3dfd52d20f46ff602be3fea8dc6ecc71aca46e6067bf5","f70abe93121637d3ec2f6c5e058ccac0307ebf63e496f38588cbfc17a8f8a264","eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e","24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c","dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591","92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a","aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878"]);
let SHA1s = dynamic(["e952c18272efa1c3d73d0a5381bcf443c02743fe","f4d77958a12a0778283d3e679b24b18f82e332c4","681075027553546c119ec447eb8df84633dcffce","f8d93c1769e877aae7e7d5c289a467b5ae371c7a"]);
let MD5s = dynamic(["98ee964edeb5a988c3bba8ea1e57fe0e","58d4eccc982c9e9b1b98aa62c514e53a","84ad78b2bab946c3677fdc28ebd8a774","95dc2289427ed29b8b996d0e3d1b78cb"]);
union
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (SHA256s) or SHA1 in (SHA1s) or MD5 in (MD5s)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (SHA256s) or SHA1 in (SHA1s) or MD5 in (MD5s)
    | project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256, SHA1, MD5, AccountName, InitiatingProcessFileName)
| order by Timestamp desc
```

### AGENTPSD-style Python reverse shell spawned by sshd on Linux / NAS

`UC_72_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="sshd" Processes.process_name IN ("python","python2","python3") (Processes.process="*socket*" OR Processes.process="*subprocess*" OR Processes.process="*pty.spawn*" OR Processes.process="*-c*import*") by Processes.dest Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName == "sshd"
| where FileName in~ ("python","python2","python3")
| where ProcessCommandLine has_any ("socket.", "subprocess.", "pty.spawn", "os.dup2", "-c import", "connect((", "/bin/sh", "/bin/bash")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Outbound endpoint connections to BRICKSTORM C2 IP 149.248.11.71

`UC_72_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.src) as src values(All_Traffic.dest_port) as dport values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="149.248.11.71" by All_Traffic.src All_Traffic.dest All_Traffic.action | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "149.248.11.71"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### pfSense / firewall config change enabling Web SSL VPN after admin login

`UC_72_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as command values(All_Changes.user) as user values(All_Changes.src) as src values(All_Changes.object) as object from datamodel=Change.All_Changes where (All_Changes.object IN ("webconfigurator","openvpn","ssl-vpn","system_advanced_admin") OR All_Changes.command IN ("openvpn-server","webgui-enable","hasync")) (sourcetype="pfsense:filterlog" OR sourcetype="pfsense:configd" OR sourcetype="pfsense") by All_Changes.dest All_Changes.action All_Changes.user | `drop_dm_object_name(All_Changes)`
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `149.248.11.71`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-22769`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ee41e06ed96182ce80cd4544a6abd5d7719c4a5c0e5ddb266a83842d39b99b0a`, `40d264cf9c73923932c3dfd52d20f46ff602be3fea8dc6ecc71aca46e6067bf5`, `f70abe93121637d3ec2f6c5e058ccac0307ebf63e496f38588cbfc17a8f8a264`, `eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e`, `24a11a26a2586f4fba7bfe89df2e21a0809ad85069e442da98c37c4add369a0c`, `dfb37247d12351ef9708cb6631ce2d7017897503657c6b882a711c0da8a9a591`, `92fb4ad6dee9362d0596fda7bbcfe1ba353f812ea801d1870e37bfc6376e624a`, `aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878` _(+12 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 26 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
