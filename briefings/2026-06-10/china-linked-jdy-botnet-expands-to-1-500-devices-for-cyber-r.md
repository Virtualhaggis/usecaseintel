# [CRIT] China-Linked JDY Botnet Expands to 1,500+ Devices for Cyber Reconnaissance

**Source:** The Hacker News
**Published:** 2026-06-10
**Article:** https://thehackernews.com/2026/06/china-linked-jdy-botnet-expands-to-1500.html

## Threat Profile

China-Linked JDY Botnet Expands to 1,500+ Devices for Cyber Reconnaissance 
 Ravie Lakshmanan  Jun 10, 2026 Botnet / Network Security 
Cybersecurity researchers have warned of a "resurgence and expansion" of JDY , a covert network associated with China-nexus state-sponsored threat actors.
"The JDY botnet comprises over 1,500 SOHO [small office and home office] and IoT devices and operates as a centrally controlled, high-performance scanner used to discover, fingerprint, and continuously map ex…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35616`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1133** — External Remote Services
- **T1595.002** — Vulnerability Scanning
- **T1590** — Gather Victim Network Information
- **T1592.002** — Software
- **T1090.003** — Multi-hop Proxy: Tor
- **T1071** — Application Layer Protocol
- **T1573** — Encrypted Channel
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Unix Shell
- **T1027.002** — Software Packing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CVE-2026-35616 edge-device exploit attempts from SOHO/residential IP space

`UC_118_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as user_agents values(Web.dest) as dest values(Web.status) as status from datamodel=Web.Web where Web.url IN ("*/cgi-bin/mainfunction.cgi*","*/HNAP1/*","*/goform/*","*ISAPI/Security/*","*/cgi-bin/luci*","*/login.cgi*") OR Web.http_user_agent IN ("*Mozilla/5.0 (compatible)*","*curl/*","*python-requests/*") by Web.src Web.dest Web.url Web.http_method | `drop_dm_object_name(Web)` | where status<500 | stats values(url) as urls values(http_method) as methods dc(dest) as victim_count by src | where victim_count>=3
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where RemoteIPType == "Public"
| where LocalPort in (80,443,8080,8443,8000,8888,4443,7547)
| summarize ConnCount = count(), DistinctTargets = dcount(DeviceId), TargetSample = make_set(DeviceName, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP
| where DistinctTargets >= 3 and ConnCount >= 10
| order by DistinctTargets desc
```

### Outbound TLS banner-grab scan fanout from single external SOHO IP

`UC_118_7` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest_port) as ports dc(All_Traffic.dest) as distinct_dest dc(All_Traffic.dest_ip) as distinct_dest_ip values(All_Traffic.app) as apps from datamodel=Network_Traffic.All_Traffic where All_Traffic.action=allowed AND All_Traffic.dest_port IN (443,8443,993,995,465,8883,9443) by All_Traffic.src All_Traffic.src_ip _time span=5m | `drop_dm_object_name(All_Traffic)` | where distinct_dest_ip >= 200 | stats sum(count) as total_conns sum(distinct_dest_ip) as total_targets values(ports) as ports_seen by src_ip | sort - total_targets
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","ConnectionFailed")
| where RemoteIPType == "Public"
| where RemotePort in (443,8443,993,995,465,8883,9443,4443)
| summarize Conns = count(), DistinctTargets = dcount(RemoteIP), TargetSample = make_set(RemoteIP, 15), DistinctPorts = dcount(RemotePort), TimeSpan = max(Timestamp) - min(Timestamp) by LocalIP, bin(Timestamp, 10m)
| where DistinctTargets >= 100 and TimeSpan < 10m
| order by DistinctTargets desc
```

### Outbound Tor connections from internal SOHO/IoT device subnets

`UC_118_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.dest_port) as dest_ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (9001,9030,9050,9051,9100,9150,443) by All_Traffic.src All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | lookup tor_exit_nodes ip as dest_ip OUTPUT is_tor | where is_tor="true" | stats values(dest_ip) as tor_relays values(dest_port) as ports sum(count) as conns by src_ip
```

**Defender KQL:**
```kql
let TorPorts = dynamic([9001, 9030, 9050, 9051, 9150]);
let TorIndicators = ThreatIntelligenceIndicator
    | where ExpirationDateTime > now() and Active == true
    | where ThreatType has "Tor" or Description has_any ("tor exit","tor relay","tor entry")
    | distinct NetworkIP;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemotePort in (TorPorts) or RemoteIP in (TorIndicators)
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, DeviceCategory, DeviceType, DeviceSubtype, Vendor, Model) by DeviceId) on DeviceId
| where DeviceCategory in~ ("NetworkDevice","IoT","Printer","SmartFacility") or DeviceType in~ ("Router","AccessPoint","NAS","Camera","NetworkPrinter") or isempty(DeviceCategory)
| project Timestamp, DeviceName, DeviceCategory, DeviceType, Vendor, Model, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

### MIPS-architecture binary download to SOHO/IoT device subnets

`UC_118_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.bytes_in) as bytes from datamodel=Web.Web where (Web.url="*mips*" OR Web.url="*mipsel*" OR Web.url="*mips64*" OR Web.url="*armv*" OR Web.url IN ("*.sh","*/bin/*")) AND Web.bytes_in>10000 by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | rex field=url "(?<arch>mips64|mipsel64|mipsel|mips|armv\d|aarch64|sh4|powerpc)" | where isnotnull(arch) | stats values(url) as urls values(arch) as arches values(http_user_agent) as agents sum(bytes) as total_bytes by src dest
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName matches regex @"(?i)(mips64|mipsel64|mipsel|mips|armv[5-7]l?|aarch64|sh4|powerpc)(\.bin|\.elf|_le|_be)?$"
      or FolderPath has_any ("/tmp/","/var/tmp/","/dev/shm/")
      and FileName matches regex @"^[a-z0-9]{1,10}$"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl, FileOriginIP, SHA256
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, DeviceCategory, DeviceType) by DeviceId) on DeviceId
| where OSPlatform in~ ("Linux","Other") or DeviceCategory in~ ("NetworkDevice","IoT","Printer")
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35616`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
