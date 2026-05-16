# [CRIT] Active Supply Chain Attack: Malicious node-ipc Versions Published to npm

**Source:** StepSecurity
**Published:** 2026-05-15
**Article:** https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack

## Threat Profile

Back to Blog Threat Intel Active Supply Chain Attack: Malicious node-ipc Versions Published to npm Active Supply Chain Attack: Malicious node-ipc Versions Published to npm StepSecurity has detected multiple malicious releases of the popular node-ipc npm package. Three versions are currently known to be compromised, containing an obfuscated payload designed to steal cloud credentials, SSH keys, and CI/CD secrets. Our team is actively analyzing the attack, and this post will be updated as our inve…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sh.azurestaticprovider.net`
- **SHA256:** `bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301`
- **SHA256:** `96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144`
- **SHA256:** `b2001dc4e13d0244f96e70258346700109907b90e1d0b09522778829dcd5e4cf`
- **SHA256:** `78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981`
- **SHA256:** `c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea`
- **SHA256:** `449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e`
- **SHA1:** `ab7388363936bf527afd4173b5728c7cdbdd01ab`
- **SHA1:** `fe5d107b9d285327af579259a32977c4f475fa26`
- **SHA1:** `58ae7338960ef525d7c655023d7c81e3ddb283d6`
- **SHA1:** `f5974a9774a22a863728b960543f68e7009099ef`
- **MD5:** `9672e9fb93a457f1d359511b4e53490d`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573** — Encrypted Channel
- **T1567** — Exfiltration Over Web Service
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1071.004** — Application Layer Protocol: DNS
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] node-ipc malicious package C2 egress to sh.azurestaticprovider.net / 37.16.75.69

`UC_24_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="37.16.75.69" OR All_Traffic.dest="sh.azurestaticprovider.net" OR All_Traffic.dest="*.azurestaticprovider.net") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name All_Traffic.process_path | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | where (process_name="node.exe" OR process_name="node" OR isnull(process_name) OR process_name="*")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "37.16.75.69"
   or RemoteUrl has "azurestaticprovider.net"
   or RemoteUrl has_cs "sh.azurestaticprovider.net"
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessSHA256, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] node-ipc DNS exfiltration via .bt.node.js suffix or direct-to-C2 resolver

`UC_24_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*.bt.node.js" OR DNS.query="*bt.node.js" OR DNS.dest="37.16.75.69") by DNS.src DNS.dest DNS.query DNS.record_type DNS.answer | `drop_dm_object_name(DNS)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="37.16.75.69" All_Traffic.dest_port=53 All_Traffic.transport="udp" by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union isfuzzy=true
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName endswith "bt.node.js" or QueryName has "bt.node.js"
    | project Timestamp, DeviceName, DeviceId, QueryName,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessAccountName ),
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP == "37.16.75.69" and RemotePort == 53 and Protocol == "Udp"
    | project Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, Protocol,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessAccountName )
| order by Timestamp desc
```

### [LLM] Malicious node-ipc.cjs bundle hash present on disk (v9.1.6 / 9.2.3 / 12.0.1)

`UC_24_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\node_modules\\node-ipc\\*" OR Filesystem.file_path="*/node_modules/node-ipc/*" OR Filesystem.file_name="node-ipc.cjs" OR Filesystem.file_hash IN ("96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144","b2001dc4e13d0244f96e70258346700109907b90e1d0b09522778829dcd5e4cf","78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981","c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea","449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e") by host Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | where (file_hash IN ("96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144","b2001dc4e13d0244f96e70258346700109907b90e1d0b09522778829dcd5e4cf","78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981","c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea","449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e") OR (file_name="node-ipc.cjs" AND file_path LIKE "%node-ipc%")) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _bad_hashes = dynamic([
  "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144",
  "b2001dc4e13d0244f96e70258346700109907b90e1d0b09522778829dcd5e4cf",
  "78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981",
  "c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea",
  "449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (_bad_hashes)
   or (FileName =~ "node-ipc.cjs" and FolderPath has "node-ipc")
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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

### Article-specific behavioural hunt — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm

`UC_24_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","node-ipc.js","bt.node.js",".bt.node.js","router_init.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/ssh/ssh_host_*" OR Filesystem.file_path="*/var/run/secrets/kubernetes.io/serviceaccount/token*" OR Filesystem.file_path="*/etc/rancher/k3s/k3s.yaml*" OR Filesystem.file_path="*/Library/Keychains/*" OR Filesystem.file_path="*/tmp/nt-1234/abc.tar.gz*" OR Filesystem.file_path="*/tmp/nt-*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js","node-ipc.js","bt.node.js",".bt.node.js","router_init.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "node-ipc.js", "bt.node.js", ".bt.node.js", "router_init.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/ssh/ssh_host_", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/etc/rancher/k3s/k3s.yaml", "/Library/Keychains/", "/tmp/nt-1234/abc.tar.gz", "/tmp/nt-", "/dev/null") or FileName in~ ("node.js", "node-ipc.js", "bt.node.js", ".bt.node.js", "router_init.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sh.azurestaticprovider.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301`, `96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144`, `b2001dc4e13d0244f96e70258346700109907b90e1d0b09522778829dcd5e4cf`, `78a82d93b4f580835f5823b85a3d9ee1f03a15ee6f0e01b4eac86252a7002981`, `c2f4dc64aec4631540a568e88932b61daebbfb7e8281b812fa01b7215f9be9ea`, `449e4265979b5fdb2d3446c021af437e815debd66de7da2fe54f1ad93cbcc75e`, `ab7388363936bf527afd4173b5728c7cdbdd01ab`, `fe5d107b9d285327af579259a32977c4f475fa26` _(+3 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
