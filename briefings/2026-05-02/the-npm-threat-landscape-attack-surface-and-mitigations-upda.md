# [CRIT] The npm Threat Landscape: Attack Surface and Mitigations (Updated May 1)

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-05-02
**Article:** https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/

## Threat Profile

Threat Research Center 
High Profile Threats 
Malware 
Malware 
The npm Threat Landscape: Attack Surface and Mitigations 
12 min read 
Related Products Advanced DNS Security Advanced URL Filtering Cloud-Delivered Security Services Cortex Cortex Cloud Unit 42 Incident Response 
By: Unit 42 
Published: April 24, 2026 
Categories: High Profile Threats 
Malware 
Tags: Credential Harvesting 
GitHub 
Npm packages 
Obfuscation 
Payload 
Supply chain 
Worm propagation 
Executive Summary 
The security of…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **IPv4 (defanged):** `94.154.172.43`
- **IPv4 (defanged):** `91.195.240.123`
- **Domain (defanged):** `audit.checkmarx.cx`
- **Domain (defanged):** `checkmarx.cx`
- **Domain (defanged):** `proton.me`
- **SHA256:** `f35475829991b303c5efc2ee0f343dd38f8614e8b5e69db683923135f85cf60d`
- **SHA256:** `18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb`
- **SHA256:** `167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad`
- **SHA1:** `bc544f455d7c06c8a1f3446160a6d9a4a8236b11`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1567.001** — Exfiltration to Code Repository

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Shai-Hulud 'Third Coming' C2 beacon to audit.checkmarx[.]cx /v1/telemetry

`UC_217_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="audit.checkmarx.cx" OR All_Traffic.dest_ip="94.154.172.43" OR All_Traffic.dest_ip="91.195.240.123") by All_Traffic.src host All_Traffic.process_name | `drop_dm_object_name("All_Traffic")` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.dest) as dest from datamodel=Web.Web where Web.url="*audit.checkmarx.cx*" OR Web.url="*/v1/telemetry*" by Web.src host Web.process_name | `drop_dm_object_name("Web")`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _c2_hosts = dynamic(["audit.checkmarx.cx"]);
let _c2_ips   = dynamic(["94.154.172.43","91.195.240.123"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (_c2_hosts))
      or (RemoteIP in (_c2_ips))
| project Timestamp, DeviceName, DeviceId,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessFolderPath,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort, ActionType
| union (
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q has "audit.checkmarx.cx" or Q endswith ".checkmarx.cx"
    | project Timestamp, DeviceName, DeviceId,
              InitiatingProcessAccountName,
              InitiatingProcessFileName,
              InitiatingProcessFolderPath,
              InitiatingProcessCommandLine,
              InitiatingProcessParentFileName,
              RemoteUrl=Q, RemoteIP=tostring(parse_json(AdditionalFields).IPAddresses),
              RemotePort=int(null), ActionType
  )
| order by Timestamp desc
```

### [LLM] Shai-Hulud preinstall: node spawning Bun runtime to execute bw1.js / setup.mjs

`UC_217_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where ( (Processes.process_name="bun" OR Processes.process_name="bun.exe") AND (Processes.process="*bw1.js*" OR Processes.process="*setup.mjs*") ) OR ( (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node" OR Processes.parent_process_name="npm" OR Processes.parent_process_name="npm.cmd") AND (Processes.process="*bw_setup.js*" OR Processes.process="*bw1.js*" OR Processes.process="*setup.mjs*") ) OR ( Processes.process="*github.com/oven-sh/bun*" AND Processes.parent_process_name IN ("node.exe","node","npm","npm.cmd","yarn.exe","pnpm.exe") ) by host Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name("Processes")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _node_parents = dynamic(["node.exe","node","npm.cmd","npm","yarn.exe","pnpm.exe","bw","bw.exe"]);
let _worm_scripts = dynamic(["bw_setup.js","bw1.js","setup.mjs","mcpAddon.js"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessAccountName !endswith "$"
| where (
      // Bun executing the obfuscated payload or worm dropper
      (FileName in~ ("bun.exe","bun")
         and ProcessCommandLine has_any (_worm_scripts))
   or // node/npm preinstall invoking the bootstrap
      (InitiatingProcessFileName in~ (_node_parents)
         and ProcessCommandLine has_any (_worm_scripts))
   or // bootstrap downloading the Bun release tarball from oven-sh
      (InitiatingProcessFileName in~ (_node_parents)
         and ProcessCommandLine has "oven-sh/bun"
         and ProcessCommandLine has_any ("curl","wget","Invoke-WebRequest","iwr"))
  )
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          GrandparentFile = InitiatingProcessParentFileName,
          ChildImage = FolderPath,
          ChildFile = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] Shai-Hulud GitHub dead-drop fallback: api.github.com search for 'beautifulcastle'

`UC_217_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.process_name) as proc from datamodel=Web.Web where Web.url="*api.github.com/search/commits*" AND Web.url="*beautifulcastle*" by host Web.src Web.dest | `drop_dm_object_name("Web")` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where (Processes.process="*beautifulcastle*" OR Processes.process="*LongLiveTheResistanceAgainstMachines*" OR Processes.process="*Checkmarx Configuration Storage*" OR Processes.process="*Shai-Hulud: The Third Coming*") AND (Processes.process_name="node.exe" OR Processes.process_name="node" OR Processes.process_name="bun.exe" OR Processes.process_name="bun" OR Processes.process_name="git.exe" OR Processes.process_name="gh.exe") by host Processes.dest Processes.user Processes.process_name | `drop_dm_object_name("Processes")`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _runtimes = dynamic(["node.exe","node","bun.exe","bun","git.exe","gh.exe","curl.exe","powershell.exe","pwsh.exe"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has "api.github.com"
    | where RemoteUrl has "search/commits" and RemoteUrl has "beautifulcastle"
    | where InitiatingProcessFileName in~ (_runtimes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName,
              RemoteUrl, RemoteIP, RemotePort, Signal="github_dead_drop_search" ),
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessAccountName !endswith "$"
    | where ProcessCommandLine has_any ("beautifulcastle",
                                        "LongLiveTheResistanceAgainstMachines",
                                        "Checkmarx Configuration Storage",
                                        "Shai-Hulud: The Third Coming",
                                        "butlerian jihad")
    | project Timestamp, DeviceName, AccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName,
              RemoteUrl="", RemoteIP="", RemotePort=int(null),
              Signal=strcat("worm_marker_string:", FileName) ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified")
    | where (FileName =~ "setup.mjs" or FileName =~ "format-check.yml")
    | where InitiatingProcessFileName in~ (_runtimes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName="",
              RemoteUrl=FolderPath, RemoteIP="", RemotePort=int(null),
              Signal=strcat("worm_artifact_written:", FileName) )
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
| where AccountName !endswith "$"
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
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — The npm Threat Landscape: Attack Surface and Mitigations (Updated May 1)

`UC_217_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The npm Threat Landscape: Attack Surface and Mitigations (Updated May 1) ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("mcpaddon.js","bw_setup.js","node.js","bw1.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("mcpaddon.js","bw_setup.js","node.js","bw1.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The npm Threat Landscape: Attack Surface and Mitigations (Updated May 1)
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("mcpaddon.js", "bw_setup.js", "node.js", "bw1.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env") or FileName in~ ("mcpaddon.js", "bw_setup.js", "node.js", "bw1.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `94.154.172.43`, `91.195.240.123`, `audit.checkmarx.cx`, `checkmarx.cx`, `proton.me`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f35475829991b303c5efc2ee0f343dd38f8614e8b5e69db683923135f85cf60d`, `18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb`, `167ce57ef59a32a6a0ef4137785828077879092d7f83ddbc1755d6e69116e0ad`, `bc544f455d7c06c8a1f3446160a6d9a4a8236b11`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
