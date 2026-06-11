# [CRIT] China-Linked JDY Botnet Expands to 1,500+ Devices for Cyber Reconnaissance

**Source:** The Hacker News, BleepingComputer
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
- **T1090.003** — Multi-hop Proxy
- **T1071** — Application Layer Protocol
- **T1059.004** — Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1595.002** — Vulnerability Scanning
- **T1046** — Network Service Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SOHO/IoT/router device outbound connection to known Tor entry/relay infrastructure

`UC_41_6` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(All_Traffic.dest_port) as dest_ports, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest_ip in ("128.31.0.39","86.59.21.38","45.66.33.45","131.188.40.189","193.23.244.244","171.25.193.9","199.58.81.140","204.13.164.118","154.35.175.225")) OR (All_Traffic.dest_port in (9001,9030) AND All_Traffic.action=allowed) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
let TorDirAuth = dynamic(["128.31.0.39","86.59.21.38","45.66.33.45","131.188.40.189","193.23.244.244","171.25.193.9","199.58.81.140","204.13.164.118","154.35.175.225"]);
let TorPorts = dynamic([9001, 9030]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemoteIP in (TorDirAuth) or RemotePort in (TorPorts)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ConnCount = count(),
            Processes = make_set(InitiatingProcessFileName, 8)
            by DeviceName, DeviceId, RemoteIP, RemotePort
| order by FirstSeen desc
```

### Internet-facing edge device with unpatched CVE-2026-35616 vulnerability

`UC_41_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
search index=vuln_mgmt sourcetype=tenable* OR sourcetype=qualys* CVE_ID="CVE-2026-35616" | join type=left dest [search index=asset_inventory internet_facing=true | fields dest, vendor, model, firmware_version] | where isnotnull(vendor) | stats min(_time) as firstSeen, max(_time) as lastSeen, values(vendor) as vendor, values(model) as model, values(firmware_version) as firmware by dest | convert ctime(firstSeen) ctime(lastSeen) | sort - lastSeen
```

**Defender KQL:**
```kql
let Vuln = DeviceTvmSoftwareVulnerabilities
    | where Timestamp > ago(7d)
    | where CveId == "CVE-2026-35616"
    | summarize arg_max(Timestamp, *) by DeviceId, CveId, SoftwareName, SoftwareVersion;
let Devs = DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, *) by DeviceId;
Vuln
| join kind=inner Devs on DeviceId
| where IsInternetFacing == true
   or DeviceCategory in~ ("NetworkDevice","IoT")
   or Vendor in~ ("Cisco","Araknis","Mimosa","Ubiquiti","Draytek","Hikvision","Linksys")
| project Timestamp, DeviceName, DeviceId, Vendor, Model, OSPlatform, OSVersion,
          SoftwareName, SoftwareVersion, PublicIP, IsInternetFacing, RecommendedSecurityUpdate
| order by Timestamp desc
```

### Architecture-specific MIPS/MIPSEL payload download via shell-script dropper

`UC_41_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent, min(_time) as firstTime from datamodel=Endpoint.Processes where (Processes.process_name="wget" OR Processes.process_name="curl" OR Processes.process_name="busybox") (Processes.process="*/mips*" OR Processes.process="*/mipsel*" OR Processes.process="*/mips64*" OR Processes.process="*/mipsel64*" OR Processes.process="*mips.bin*" OR Processes.process="*mipsel.bin*") (Processes.parent_process_name="sh" OR Processes.parent_process_name="bash" OR Processes.parent_process_name="dash" OR Processes.parent_process_name="ash" OR Processes.parent_process_name="busybox") by host, Processes.user, Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wget","curl","busybox")
| where ProcessCommandLine has_any ("/mips","/mipsel","/mips64","/mipsel64","mips.bin","mipsel.bin",".mips",".mipsel")
| where InitiatingProcessFileName in~ ("sh","bash","dash","ash","busybox","zsh")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### High-fanout outbound scanning from internal host — potential JDY bot reconnaissance

`UC_41_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t dc(All_Traffic.dest_ip) as distinctDestIPs, dc(All_Traffic.dest_port) as distinctDestPorts, count from datamodel=Network_Traffic where All_Traffic.src_category=internal NOT All_Traffic.src_category=scanner by All_Traffic.src, _time span=5m | `drop_dm_object_name(All_Traffic)` | where distinctDestIPs > 200 AND distinctDestPorts > 20 AND count > 500 | sort - distinctDestIPs
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType in ("ConnectionAttempt","ConnectionSuccess","ConnectionFailed")
| where RemoteIPType == "Public"
| summarize DistinctRemoteIPs = dcount(RemoteIP),
            DistinctRemotePorts = dcount(RemotePort),
            ConnCount = count(),
            SamplePorts = make_set(RemotePort, 25),
            SampleProcs = make_set(InitiatingProcessFileName, 10)
            by DeviceName, DeviceId, bin(Timestamp, 5m)
| where DistinctRemoteIPs > 200 and DistinctRemotePorts > 20 and ConnCount > 500
| order by DistinctRemoteIPs desc
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

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
