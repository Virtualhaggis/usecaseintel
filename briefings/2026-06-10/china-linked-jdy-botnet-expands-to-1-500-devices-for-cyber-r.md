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
- **T1046** — Network Service Discovery
- **T1595.002** — Vulnerability Scanning
- **T1059.004** — Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1070.004** — File Deletion
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1008** — Fallback Channels
- **T1087** — Account Discovery
- **T1018** — Remote System Discovery
- **T1016** — System Network Configuration Discovery
- **T1082** — System Information Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### High-fanout TCP SYN scanning sourced from internal SOHO/IoT subnet

`UC_115_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Traffic.dest_ip) as DistinctDestIPs dc(All_Traffic.dest_port) as DistinctDestPorts count from datamodel=Network_Traffic where All_Traffic.action="blocked" OR All_Traffic.tcp_flag="SYN" by All_Traffic.src_ip _time span=10m | `drop_dm_object_name("All_Traffic")` | where DistinctDestIPs > 200 AND DistinctDestPorts > 10 | sort - DistinctDestIPs
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType in ("ConnectionAttempt","ConnectionFailed")
| where RemoteIPType == "Public"
| where Protocol =~ "Tcp"
| summarize DistinctDestIPs = dcount(RemoteIP), DistinctDestPorts = dcount(RemotePort), AttemptCount = count(), TopPorts = make_set(RemotePort, 20) by DeviceId, DeviceName, bin(Timestamp, 10m)
| where DistinctDestIPs > 200 and DistinctDestPorts > 10
| order by DistinctDestIPs desc
```

### JDY MIPS architecture payload download via shell script dropper

`UC_115_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("sh","bash","ash","busybox") AND (Processes.process="*uname*" OR Processes.process="*/proc/cpuinfo*") AND (Processes.process="*mips*" OR Processes.process="*mipsel*" OR Processes.process="*mips64*") by Processes.dest Processes.user | `drop_dm_object_name("Processes")` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("sh","bash","ash","dash","busybox")
| where ProcessCommandLine has_any ("mipsel64","mipsel","mips64"," mips ")
   and ProcessCommandLine has_any ("wget","curl","tftp","ftpget","busybox wget")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

### Coordinated periodic beaconing fanout across many internal devices

`UC_115_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Traffic.src_ip) as DistinctSources values(All_Traffic.src_ip) as src_ips from datamodel=Network_Traffic where All_Traffic.dest_category="public" by All_Traffic.dest_ip All_Traffic.dest_port _time span=1h | `drop_dm_object_name("All_Traffic")` | where DistinctSources >= 20 AND count < 5000 | stats sum(count) as TotalConns sum(DistinctSources) as TotalSourceFanout values(src_ips) as Sources by dest_ip dest_port | where TotalSourceFanout >= 50 | sort - TotalSourceFanout
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443, 53)
| summarize DistinctSources = dcount(DeviceId), TotalConns = count(), Sources = make_set(DeviceName, 50), MeanIntervalSec = avg(datetime_diff('second', Timestamp, prev(Timestamp))) by RemoteIP, RemotePort, bin(Timestamp, 1h)
| where DistinctSources >= 20
| summarize PeakFanout = max(DistinctSources), TotalSourceFanout = sum(DistinctSources), TotalConns = sum(TotalConns), Sources = make_set(Sources, 100) by RemoteIP, RemotePort
| where TotalSourceFanout >= 50
| order by TotalSourceFanout desc
```

### Mass internal-recon command bursts across multiple hosts

`UC_115_9` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.process_name IN ("net.exe","net1.exe","ipconfig.exe","arp.exe","systeminfo.exe","nbtstat.exe","nltest.exe","dsquery.exe") AND Processes.user!="*$" by Processes.dest Processes.user _time span=1h | `drop_dm_object_name("Processes")` | stats dc(dest) as DistinctHosts values(dest) as Hosts sum(count) as TotalCmds by user _time | where DistinctHosts >= 10 | sort - DistinctHosts
```

**Defender KQL:**
```kql
let RecceBinaries = dynamic(["net.exe","net1.exe","ipconfig.exe","arp.exe","systeminfo.exe","nbtstat.exe","nltest.exe","dsquery.exe","whoami.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ (RecceBinaries)
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| summarize Hosts = dcount(DeviceId), HostNames = make_set(DeviceName, 30), Cmds = make_set(ProcessCommandLine, 50), TotalExecs = count() by AccountName, bin(Timestamp, 1h)
| where Hosts >= 10
| order by Hosts desc
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
