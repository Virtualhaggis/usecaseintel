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
- **T1595.001** — Scanning IP Blocks
- **T1595.002** — Vulnerability Scanning
- **T1590** — Gather Victim Network Information
- **T1046** — Network Service Discovery
- **T1571** — Non-Standard Port
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Unix Shell
- **T1070.004** — File Deletion
- **T1027.002** — Software Packing
- **T1590.005** — Gather Victim Network Information: IP Addresses
- **T1583.005** — Acquire Infrastructure: Botnet

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JDY botnet inbound multi-protocol reconnaissance fingerprint

`UC_115_6` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.dest_port) as distinct_dst_ports, dc(All_Traffic.transport) as distinct_protocols, dc(All_Traffic.dest) as internal_targets, values(All_Traffic.transport) as protocols_seen, values(All_Traffic.dest_port) as ports_seen from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_category!="internal" AND All_Traffic.dest_category="internal" by All_Traffic.src, _time span=10m | `drop_dm_object_name(All_Traffic)` | where distinct_protocols>=2 AND distinct_dst_ports>=10 AND internal_targets>=3 | rename src as scanner_ip | sort -count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType in ("InboundConnectionAccepted","ConnectionAttempt","ConnectionSuccess")
| where RemoteIPType == "Public" and LocalIPType != "Public"
| summarize ProtocolsSeen=make_set(Protocol), PortsSeen=make_set(LocalPort), DistinctProtocols=dcount(Protocol), DistinctPorts=dcount(LocalPort), InternalTargets=dcount(DeviceId), HitCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by RemoteIP, bin(Timestamp, 10m)
| where DistinctProtocols >= 2 and DistinctPorts >= 10 and InternalTargets >= 2
| where ProtocolsSeen has_any ("Icmp","Udp") and ProtocolsSeen has "Tcp"
| order by HitCount desc
```

### Internal SOHO/IoT device emitting outbound SYN scan storm (JDY-infected node)

`UC_115_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.dest) as distinct_dst_ips, dc(All_Traffic.dest_port) as distinct_dst_ports, values(All_Traffic.dest_port) as ports_targeted from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_category="internal" AND All_Traffic.dest_category!="internal" AND All_Traffic.transport="tcp" AND All_Traffic.action!="allowed" by All_Traffic.src, _time span=5m | `drop_dm_object_name(All_Traffic)` | where distinct_dst_ips>=100 AND distinct_dst_ports>=5 | rename src as bot_host_ip | sort -distinct_dst_ips
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where ActionType in ("ConnectionAttempt","ConnectionFailed")
| where Protocol == "Tcp" and RemoteIPType == "Public"
| summarize DistinctRemoteIPs=dcount(RemoteIP), DistinctPorts=dcount(RemotePort), Probes=count(), PortsTargeted=make_set(RemotePort,50), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Initiators=make_set(InitiatingProcessFileName,20) by DeviceId, DeviceName, bin(Timestamp, 5m)
| where DistinctRemoteIPs >= 100
| where Probes >= 200
| extend RatePerMin = todouble(Probes) / 5.0
| order by DistinctRemoteIPs desc
```

### Architecture-aware shell-script dropper with self-deletion (MIPS/MIPSEL payload)

`UC_115_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Processes.process) as cmdlines, values(Processes.parent_process_name) as parents, min(_time) as first_seen, max(_time) as last_seen from datamodel=Endpoint.Processes where Processes.process_name IN ("wget","curl","sh","bash","busybox","ash") AND (Processes.process="*mips*" OR Processes.process="*mipsel*" OR Processes.process="*mips64*" OR Processes.process="*mipsel64*" OR Processes.process="*armv*" OR Processes.process="*arm5*" OR Processes.process="*arm7*") AND (Processes.process="*chmod*" OR Processes.process="*+x*" OR Processes.process="*/tmp/*" OR Processes.process="*/var/run/*") by Processes.dest, Processes.user, Processes.process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName !endswith "$"
| where InitiatingProcessFileName in~ ("sh","bash","busybox","ash","dash") or FileName in~ ("wget","curl","tftp")
| where ProcessCommandLine matches regex @"(?i)(mips(el|64)?|mipsel64|armv[4-7]l?|arm5|arm7|sh4|powerpc|x86_64|i[3-6]86)"
| where ProcessCommandLine has_any ("/tmp/","/var/run/","/dev/shm/","/var/tmp/")
| where ProcessCommandLine has_any ("chmod"," +x","wget ","curl ","tftp ")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Distributed SOHO-class scanning against same internal asset (JDY botnet fan-in)

`UC_115_9` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.src) as distinct_scanner_ips, values(All_Traffic.src) as scanner_ips, dc(All_Traffic.dest_port) as ports_probed from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_category!="internal" AND All_Traffic.dest_category="internal" by All_Traffic.dest, All_Traffic.dest_port, _time span=1h | `drop_dm_object_name(All_Traffic)` | where distinct_scanner_ips>=5 | iplocation scanner_ips | stats sum(count) as total_probes, dc(scanner_ips) as scanner_count, values(Country) as scanner_countries by dest, dest_port | where scanner_count>=5
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType in ("InboundConnectionAccepted","ConnectionAttempt","ConnectionSuccess")
| where RemoteIPType == "Public" and LocalIPType != "Public"
| summarize DistinctScannerIPs=dcount(RemoteIP), ScannerSample=make_set(RemoteIP,20), ProbeCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceId, DeviceName, LocalPort, Protocol, bin(Timestamp, 1h)
| where DistinctScannerIPs >= 5
| where ProbeCount >= 15
| where LocalPort in (22, 23, 80, 443, 161, 502, 1883, 5000, 8000, 8080, 8443, 8291, 7547, 37777, 554, 9000, 9999)
| order by DistinctScannerIPs desc
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

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
