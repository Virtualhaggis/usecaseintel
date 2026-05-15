# [CRIT] Sandworm Hackers Pivot From Compromised IT Systems Toward Critical OT Assets

**Source:** Cyber Security News
**Published:** 2026-05-14
**Article:** https://cybersecuritynews.com/sandworm-hackers-pivot-from-compromised-it-systems/

## Threat Profile

Home Cyber Security News 
Sandworm Hackers Pivot From Compromised IT Systems Toward Critical OT Assets 
By Tushar Subhra Dutta 
May 14, 2026 
A Russian state-sponsored hacking group known as Sandworm has been caught making a calculated pivot from compromised IT networks into operational technology systems that control physical infrastructure. 
The campaign is alarming because it does not rely on cutting-edge exploits. Instead, Sandworm walks through doors that were already left open, turning unr…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1195.002** — Compromise Software Supply Chain
- **T1210** — Exploitation of Remote Services
- **T1021.002** — Remote Services: SMB/Windows Admin Shares
- **T0866** — Exploitation of Remote Services (ICS)
- **T1071.004** — Application Layer Protocol: DNS
- **T1568** — Dynamic Resolution
- **T0883** — Internet Accessible Device (ICS)
- **T0846** — Remote System Discovery (ICS)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sandworm SMB lateral fan-out — single source hitting many internal port 445 hosts

`UC_18_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.dest) AS unique_targets, values(All_Traffic.dest) AS targets, values(All_Traffic.action) AS actions FROM datamodel=Network_Traffic.All_Traffic WHERE All_Traffic.dest_port=445 AND All_Traffic.transport=tcp BY All_Traffic.src _time span=1h
| `drop_dm_object_name("All_Traffic")`
| where unique_targets > 50
| where (like(src,"10.%") OR like(src,"172.16.%") OR like(src,"172.17.%") OR like(src,"172.18.%") OR like(src,"172.19.%") OR like(src,"172.2_.%") OR like(src,"172.3_.%") OR like(src,"192.168.%"))
| where NOT match(src,"^(10\.99\.1\.|10\.0\.250\.)")  /* exclude tenant vuln-scanner/Nessus/Qualys IPs */
| sort 0 - unique_targets
```

**Defender KQL:**
```kql
// Sandworm SMB fan-out: single host attempts SMB to 50+ unique internal targets in 1h
// Tune _known_scanners with your authorised internal scanners (Nessus, Qualys, Tenable, Defender for IoT sensors)
let _known_scanners = dynamic(["NESSUS-SCANNER-01","QUALYS-SCAN-01"]);
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 445
| where Protocol == "Tcp"
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","ConnectionFailed")
| where RemoteIPType in ("Private","Reserved")
| where DeviceName !in~ (_known_scanners)
| summarize
    UniqueTargets = dcount(RemoteIP),
    SampleTargets = make_set(RemoteIP, 100),
    SuccessCount  = countif(ActionType == "ConnectionSuccess"),
    AttemptCount  = countif(ActionType == "ConnectionAttempt"),
    FailedCount   = countif(ActionType == "ConnectionFailed"),
    InitiatingProcs = make_set(InitiatingProcessFileName, 20),
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp)
    by DeviceName, DeviceId, LocalIP, bin(Timestamp, 1h)
| where UniqueTargets > 50      // Nozomi observed 405 hosts from one source; 50 is a conservative floor
| order by UniqueTargets desc
```

### [LLM] WannaCry kill-switch domain DNS query (Sandworm pre-compromise indicator)

`UC_18_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(DNS.src) AS src, values(DNS.dest) AS resolver, min(_time) AS firstTime, max(_time) AS lastTime FROM datamodel=Network_Resolution.DNS WHERE (DNS.query="iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" OR DNS.query="ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com" OR DNS.query="www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" OR DNS.query="www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com") BY DNS.src DNS.query
| `drop_dm_object_name("DNS")`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// WannaCry kill-switch resolution — indicates an unremediated WannaCry/Sandworm-foothold host
let _killswitch = dynamic([
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
    "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
]);
let _killswitch_substr = dynamic([
    "iuqerfsodp9ifjaposdfjh",     // catches www.* and subdomain variants
    "ifferfsodp9ifjaposdfjh"
]);
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
| where QueryName in (_killswitch) or QueryName has_any (_killswitch_substr)
| project Timestamp, DeviceName, DeviceId, QueryName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Sandworm IT→OT pivot — ICS protocol fan-out during Moscow work-window

`UC_18_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(All_Traffic.dest) AS unique_ot_targets, dc(All_Traffic.dest_port) AS unique_ports, values(All_Traffic.dest_port) AS ports, values(All_Traffic.dest) AS targets FROM datamodel=Network_Traffic.All_Traffic WHERE (All_Traffic.dest_port=445 OR All_Traffic.dest_port=502 OR All_Traffic.dest_port=102 OR All_Traffic.dest_port=44818 OR All_Traffic.dest_port=20000 OR All_Traffic.dest_port=2222 OR All_Traffic.dest_port=2404 OR All_Traffic.dest_port=4840 OR All_Traffic.dest_port=3389 OR All_Traffic.dest_port=5985 OR All_Traffic.dest_port=5986) BY All_Traffic.src _time span=30m
| `drop_dm_object_name("All_Traffic")`
| eval src_hour=strftime(_time,"%H"), src_wday=strftime(_time,"%A")
| where unique_ot_targets >= 20
| where src_wday="Wednesday" AND src_hour>="10" AND src_hour<="12"  /* ~14:00 Moscow = ~11:00 UTC */
| sort 0 - unique_ot_targets
```

**Defender KQL:**
```kql
// Sandworm ICS-protocol fan-out during Wed ~14:00 Moscow (~10-12 UTC)
// Ports: 445 SMB (Eng WS), 502 Modbus, 102 S7/ISO-TSAP, 44818 EtherNet/IP, 20000 DNP3,
//        2222 EtherNet/IP-IO, 2404 IEC-104, 4840 OPC-UA, 3389 RDP, 5985/5986 WinRM
let _ics_ports = dynamic([445, 502, 102, 44818, 20000, 2222, 2404, 4840, 3389, 5985, 5986]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemotePort in (_ics_ports)
| where RemoteIPType in ("Private","Reserved")
| where dayofweek(Timestamp) == 3d                       // Wednesday
| where hourofday(Timestamp) between (10 .. 12)          // 10:00-12:00 UTC ~ 13:00-15:00 Moscow
| summarize
    UniqueOtTargets = dcount(RemoteIP),
    DistinctIcsPorts = dcount(RemotePort),
    PortList = make_set(RemotePort),
    SampleTargets = make_set(RemoteIP, 50),
    InitiatingProcs = make_set(InitiatingProcessFileName, 20),
    SampleCmd = any(InitiatingProcessCommandLine),
    FirstSeen = min(Timestamp),
    LastSeen  = max(Timestamp)
    by DeviceName, DeviceId, bin(Timestamp, 30m)
| where UniqueOtTargets >= 20 and DistinctIcsPorts >= 2   // hitting many hosts AND multiple ICS ports — not just RDP admin work
| order by UniqueOtTargets desc
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
