# [HIGH] Hackers Abuse Shared CDN Edge IPs to Bypass Protective DNS Filtering

**Source:** Cyber Security News
**Published:** 2026-05-28
**Article:** https://cybersecuritynews.com/cdn-edge-ips-bypass-dns-filtering/

## Threat Profile

Home Cyber Security News 
Hackers Abuse Shared CDN Edge IPs to Bypass Protective DNS Filtering 
By Abinaya 
May 28, 2026 




Hackers are increasingly abusing shared Content Delivery Network (CDN) infrastructure to bypass protective DNS filtering, according to new research from ADAMnetworks, which has identified a stealthy technique allowing malicious traffic to hide behind trusted domains.
The method, dubbed “Underminr,” exploits gaps in how security systems validate DNS requests, TLS conne…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1090.004** — Proxy: Domain Fronting
- **T1133** — External Remote Services
- **T1090** — Proxy
- **T1016** — System Network Configuration Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Direct-to-IP TLS egress to shared CDN edge ranges by non-browser process (Underminr Direct-to-IP Mode)

`UC_2_5` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ips dc(All_Traffic.dest_ip) as distinct_ips from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=443 All_Traffic.dest_category!="internal" NOT (All_Traffic.app IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")) by All_Traffic.src host All_Traffic.app All_Traffic.dest_ip span=10m | `drop_dm_object_name(All_Traffic)` | where distinct_ips>=3 OR count>=5 | sort - lastTime
```

**Defender KQL:**
```kql
let lookback = 1h;
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe","safari.exe","vivaldi.exe"]);
let directIp = DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("ConnectionSuccess","ConnectionAttempt")
    | where RemotePort == 443
    | where RemoteIPType == "Public"
    | where isempty(RemoteUrl)                                     // no SNI / hostname captured = direct-to-IP
    | where InitiatingProcessFileName !in~ (browsers)
    | where InitiatingProcessFolderPath !startswith @"C:\Windows\System32\"
    | where InitiatingProcessAccountName !endswith "$"
    | where InitiatingProcessAccountName !in~ ("system","local service","network service");
directIp
| summarize Connections = count(),
            DistinctIPs = dcount(RemoteIP),
            SampleIPs = make_set(RemoteIP, 10),
            SampleCmd = any(InitiatingProcessCommandLine),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where Connections >= 5 or DistinctIPs >= 3                       // 3+ distinct public IPs in 10 min from non-browser = direct-to-IP pattern
| order by LastSeen desc
```

### [LLM] SoftEther VPN client/server binaries linked to Flax Typhoon / GALLIUM Underminr operations

`UC_2_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_hash) as hashes values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name IN ("vpncmd.exe","vpnclient.exe","vpnclient_x64.exe","vpnserver.exe","vpnserver_x64.exe","vpnbridge.exe","vpnsmgr.exe") OR Processes.process IN ("*SecureNAT*","*RemoteEnable*","*ListenerCreate*","*HubCreate*","*BridgeCreate*","*AccountCreate*")) by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | where user!="*$" | sort - lastTime
```

**Defender KQL:**
```kql
let softetherBins = dynamic(["vpncmd.exe","vpnclient.exe","vpnclient_x64.exe","vpnserver.exe","vpnserver_x64.exe","vpnbridge.exe","vpnsmgr.exe","vpninstall.exe"]);
let softetherTokens = dynamic(["SecureNAT","RemoteEnable","ListenerCreate","HubCreate","BridgeCreate","AccountCreate","CascadeCreate","NicCreate","SstpEnable"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName in~ (softetherBins))
   or  (InitiatingProcessFileName in~ (softetherBins))
   or  (ProcessCommandLine has_any (softetherTokens))
| where AccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256, ProcessVersionInfoCompanyName
| order by Timestamp desc
```

### [LLM] IP-check / geolocation lookup by non-browser process (Underminr decoy reconnaissance)

`UC_2_7` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as queries from datamodel=Network_Resolution.DNS where DNS.query IN ("whatismyipaddress.com","*.whatismyipaddress.com","ipify.org","api.ipify.org","ipinfo.io","ifconfig.me","icanhazip.com","checkip.amazonaws.com","ip-api.com","myexternalip.com","ident.me") by host DNS.src DNS.process_name | `drop_dm_object_name(DNS)` | where NOT process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe","safari.exe") | sort - lastTime
```

**Defender KQL:**
```kql
let ipCheckDomains = dynamic(["whatismyipaddress.com","ipify.org","api.ipify.org","ipinfo.io","ifconfig.me","icanhazip.com","checkip.amazonaws.com","ip-api.com","myexternalip.com","ident.me","ipecho.net"]);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe","safari.exe","vivaldi.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (ipCheckDomains)
| where InitiatingProcessFileName !in~ (browsers)
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("onedrive.exe","teams.exe","zoom.exe","slack.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 8 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
