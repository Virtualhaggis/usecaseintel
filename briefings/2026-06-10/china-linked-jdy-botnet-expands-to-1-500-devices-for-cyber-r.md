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
- **T1105** — Ingress Tool Transfer
- **T1027.009** — Embedded Payloads
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1090.003** — Multi-hop Proxy
- **T1046** — Network Service Discovery
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1595.002** — Active Scanning: Vulnerability Scanning

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Inventory: edge devices vulnerable to CVE-2026-35616 (JDY botnet target)

`UC_121_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.signature="*CVE-2026-35616*" OR (Vulnerabilities.vendor IN ("cisco","araknis","mimosa","ubiquiti","draytek","hikvision","linksys") AND Vulnerabilities.product IN ("RV320","RV325","router","firewall","camera","access point")) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.vendor Vulnerabilities.product Vulnerabilities.severity | `drop_dm_object_name("Vulnerabilities")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId =~ "CVE-2026-35616"
   or (SoftwareVendor in~ ("cisco","araknis","mimosa networks","mimosa","ubiquiti","ubiquiti networks","draytek","hikvision","linksys")
       and SoftwareName has_any ("rv320","rv325","router","firewall","camera","nvr","access point","ap"))
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, DeviceCategory, DeviceType, IsInternetFacing, PublicIP) by DeviceId) on DeviceId
| project Timestamp, DeviceName, DeviceCategory, DeviceType, IsInternetFacing, PublicIP, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by VulnerabilitySeverityLevel asc, Timestamp desc
```

### JDY shell-script dropper: MIPS/MIPSEL architecture payload download

`UC_121_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Web.url) as urls, values(Web.http_user_agent) as agents from datamodel=Web.Web where (Web.url="*.mips" OR Web.url="*.mipsel" OR Web.url="*.mips64" OR Web.url="*.mipsel64" OR Web.url="*/mips" OR Web.url="*/mipsel" OR Web.url="*/mips64" OR Web.url="*/mipsel64" OR Web.url="*payload*mips*" OR Web.url="*bot*mips*") by Web.src Web.dest _time | `drop_dm_object_name("Web")` | where count > 0
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| where RemoteUrl matches regex @"(?i)(/|[._-])(mips|mipsel|mips64|mipsel64)(\.|/|\?|$)"
| project Timestamp, DeviceName, DeviceId, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### JDY Tor-based C2 beaconing from internal SOHO/edge/IoT device IPs

`UC_121_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.dest_ip) as DistinctDest, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (9001,9030,9050,9051,9150) AND All_Traffic.direction=outbound AND All_Traffic.action=allowed by All_Traffic.src_ip All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")` | where count > 5 AND DistinctDest > 2 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let TorPorts = dynamic([9001, 9030, 9050, 9051, 9150]);
let LegitTorProcs = dynamic(["tor.exe","tor-browser.exe","firefox.exe","brave.exe","torbrowser.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where RemotePort in (TorPorts)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where InitiatingProcessFileName !in~ (LegitTorProcs)
| summarize ConnCount = count(),
            DistinctRemoteIPs = dcount(RemoteIP),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleProc = any(InitiatingProcessCommandLine),
            SampleRemote = any(RemoteIP)
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemotePort
| where ConnCount > 5 and DistinctRemoteIPs > 2
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| order by ConnCount desc
```

### Inbound SYN/SSL scan burst from JDY-style SOHO source IP

`UC_121_9` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.dest_ip) as DestIPs, dc(All_Traffic.dest_port) as DestPorts, values(All_Traffic.transport) as Transports from datamodel=Network_Traffic.All_Traffic where All_Traffic.action IN ("blocked","denied","dropped") AND All_Traffic.direction=inbound by All_Traffic.src_ip _time span=10m | `drop_dm_object_name("All_Traffic")` | where DestPorts >= 50 AND DestIPs >= 20 AND count >= 100 | sort - count
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

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
