# [CRIT] Cracks in the Bedrock: Escaping the AWS AgentCore Sandbox

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-04-07
**Article:** https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/

## Threat Profile

Threat Research Center 
Threat Research 
Malware 
Malware 
Cracks in the Bedrock: Escaping the AWS AgentCore Sandbox 
13 min read 
Related Products Cortex Cortex Cloud Unit 42 AI Security Assessment Unit 42 Cloud Security Assessment Unit 42 Incident Response 
By: Ori Hadad 
Published: April 7, 2026 
Categories: Malware 
Threat Research 
Tags: Agentcore 
Agentcore runtime 
AWS 
DNS tunneling 
GenAI 
Sandbox 
Executive Summary 
When researching the boundaries of cloud services, two of the main asp…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **Domain (defanged):** `dnshook.site`
- **Domain (defanged):** `my-secret.dnshook.site`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071.004** — Application Layer Protocol: DNS
- **T1048.003** — Exfiltration Over Alternative Protocol: Unencrypted/Obfuscated
- **T1572** — Protocol Tunneling

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DNS queries to dnshook.site (Unit42/BeyondTrust AgentCore sandbox-escape PoC domain)

`UC_240_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Network_Resolution.query) as queries values(Network_Resolution.answer) as answers from datamodel=Network_Resolution where (Network_Resolution.query="dnshook.site" OR Network_Resolution.query="*.dnshook.site") by Network_Resolution.src Network_Resolution.dest_domain Network_Resolution.record_type | `drop_dm_object_name(Network_Resolution)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
// AgentCore sandbox-escape PoC domain (Unit 42 + BeyondTrust corroborated)
let _pocDomain = "dnshook.site";
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
| where QueryName == _pocDomain or QueryName endswith strcat(".", _pocDomain)
| project Timestamp, DeviceName, DeviceId, QueryName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, AdditionalFields
| order by Timestamp desc
```

### [LLM] AgentCore-style DNS tunnelling: high-volume long-label subdomain queries to a single parent domain

`UC_240_10` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as queryCount values(Network_Resolution.query) as sampleQueries dc(Network_Resolution.query) as distinctSubdomains from datamodel=Network_Resolution where Network_Resolution.record_type IN ("A","AAAA","TXT","CNAME") by Network_Resolution.src _time span=10m | `drop_dm_object_name(Network_Resolution)` | eval parentDomain=mvindex(split(mvindex(sampleQueries,0),"."),-2)+"."+mvindex(split(mvindex(sampleQueries,0),"."),-1) | stats sum(queryCount) as totalQueries sum(distinctSubdomains) as totalDistinct values(sampleQueries) as sampleQueries by src parentDomain | eval avgLabelLen=mvindex(mvfilter(len(sampleQueries)>30),0) | where totalDistinct >= 50 AND totalQueries >= 100 AND len(parentDomain) > 5 | sort - totalDistinct
```

**Defender KQL:**
```kql
// AgentCore-style DNS exfil pattern: many long-label subdomains under one parent
let _windowMin = 10m;
let _minDistinctLabels = 50;     // article: each query encodes a chunk
let _minLabelLen = 30;            // base64 chunks are typically long
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
| where isnotempty(QueryName) and QueryName contains "."
| extend Labels = split(QueryName, ".")
| where array_length(Labels) >= 3
| extend ParentDomain = strcat(tostring(Labels[array_length(Labels)-2]), ".", tostring(Labels[array_length(Labels)-1]))
| extend FirstLabel = tostring(Labels[0])
| extend FirstLabelLen = strlen(FirstLabel)
| where FirstLabelLen >= _minLabelLen
| where FirstLabel matches regex @"^[A-Za-z0-9+/=_-]+$"      // base64-ish / hex / b32
| summarize DistinctSubdomains = dcount(QueryName),
            QueryCount = count(),
            MaxLabelLen = max(FirstLabelLen),
            SampleQueries = make_set(QueryName, 5),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceId, DeviceName, ParentDomain, InitiatingProcessFileName, bin(Timestamp, _windowMin)
| where DistinctSubdomains >= _minDistinctLabels
| where ParentDomain !endswith ".amazonaws.com"
      and ParentDomain !endswith ".microsoft.com"
      and ParentDomain !endswith ".windowsupdate.com"
      and ParentDomain !endswith ".akadns.net"          // CDN/ESI noise suppression
      and ParentDomain !endswith ".akamaiedge.net"
      and ParentDomain !endswith ".cloudfront.net"
| order by DistinctSubdomains desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `dnshook.site`, `my-secret.dnshook.site`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
