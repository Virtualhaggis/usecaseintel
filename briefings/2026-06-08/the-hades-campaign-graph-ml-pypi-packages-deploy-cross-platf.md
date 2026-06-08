# [HIGH] The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers, AI Analyst Misdirection, and a Wiper Deterrent

**Source:** StepSecurity
**Published:** 2026-06-08
**Article:** https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages

## Threat Profile

Back to Blog Threat Intel The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers, AI Analyst Misdirection, and a Wiper Deterrent Rohan Prabhu View LinkedIn June 8, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Summary On June 8, 2026, version 0.8.101 of the popular graph machine learning package ensmallen on PyPI was identified as containing a highly sophisticated supply chain compromise. Concurrent…

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
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1543.001** — Persistence (article-specific)
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1140** — Deobfuscate/Decode Files or Information
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.001** — Exfiltration to Code Repository
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1003** — OS Credential Dumping
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1057** — Process Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Hades Campaign PyPI install of compromised graph-ML / bio package versions

`UC_0_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip","pip.exe","pip3","pip3.exe","uv","uv.exe","poetry","poetry.exe")) AND (Processes.process IN ("*ensmallen==0.8.101*","*ensmallen-0.8.101*","*embiggen==0.11.97*","*embiggen-0.11.97*","*gpsea==0.9.14*","*gpsea-0.9.14*","*pyphetools==0.9.120*","*pyphetools-0.9.120*","*mflux-streamlit==0.0.3*","*mflux-streamlit==0.0.4*","*mflux_streamlit-0.0.3*","*mflux_streamlit-0.0.4*","*nhmpy==2.4.7*","*nhmpy-2.4.7*","*ppkt2synergy==0.1.1*","*ppkt2synergy-0.1.1*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let HadesPkgVersions = dynamic(["ensmallen==0.8.101","ensmallen-0.8.101","embiggen==0.11.97","embiggen-0.11.97","gpsea==0.9.14","gpsea-0.9.14","pyphetools==0.9.120","pyphetools-0.9.120","mflux-streamlit==0.0.3","mflux-streamlit==0.0.4","mflux_streamlit-0.0.3","mflux_streamlit-0.0.4","nhmpy==2.4.7","nhmpy-2.4.7","ppkt2synergy==0.1.1","ppkt2synergy-0.1.1"]);
let HadesDistInfo = dynamic(["ensmallen-0.8.101.dist-info","embiggen-0.11.97.dist-info","gpsea-0.9.14.dist-info","pyphetools-0.9.120.dist-info","mflux_streamlit-0.0.3.dist-info","mflux_streamlit-0.0.4.dist-info","nhmpy-2.4.7.dist-info","ppkt2synergy-0.1.1.dist-info"]);
union
(DeviceProcessEvents
 | where Timestamp > ago(7d)
 | where FileName in~ ("pip","pip.exe","pip3","pip3.exe","uv","uv.exe","poetry","poetry.exe") or InitiatingProcessFileName in~ ("pip","pip.exe","pip3","pip3.exe")
 | where ProcessCommandLine has_any (HadesPkgVersions)
 | project Timestamp, DeviceName, AccountName, Surface="process", FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents
 | where Timestamp > ago(7d)
 | where ActionType == "FileCreated"
 | where FolderPath has_any (HadesDistInfo) or FileName has_any (HadesPkgVersions)
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Surface="file", FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine="", FolderPath)
| order by Timestamp desc
```

### [LLM] Hades Campaign python import hook spawning bun runtime from /tmp

`UC_0_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python.exe","python3","python3.exe","python3.11","python3.12","python3.13") AND (Processes.process_name IN ("bun","bun.exe") OR Processes.process_path IN ("*/tmp/b/bun","*\\Temp\\b\\bun.exe") OR Processes.process IN ("*\\tmp\\b\\bun*","*/tmp/b/bun*","*_index.js*","*bun*run*_index.js*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has "python" or InitiatingProcessParentFileName has "python"
| where (FileName =~ "bun" or FileName =~ "bun.exe")
      or FolderPath has_any (@"/tmp/b/", @"\Temp\b\", @"\AppData\Local\Temp\b\")
      or ProcessCommandLine has_any ("/tmp/b/bun", @"\Temp\b\bun", "_index.js")
| extend BunPath = FolderPath, BunCmd = ProcessCommandLine
| project Timestamp, DeviceName, AccountName, BunPath, BunCmd,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Hades Campaign persistence artifacts (systemd units + updater.py + lock/state files)

`UC_0_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.config/systemd/user/update-monitor.service","*/.config/systemd/user/gh-token-monitor.service","*/.local/share/updater/update.py","*/.local/share/updater/updater.py","/tmp/.bun_ran","/tmp/tmp.0144018410.lock","/var/tmp/.gh_update_state") OR Filesystem.file_name IN ("update-monitor.service","gh-token-monitor.service","tmp.0144018410.lock",".bun_ran",".gh_update_state")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let HadesFiles = dynamic(["update-monitor.service","gh-token-monitor.service",".bun_ran",".gh_update_state","tmp.0144018410.lock"]);
let HadesPaths = dynamic(["/.config/systemd/user/update-monitor.service","/.config/systemd/user/gh-token-monitor.service","/.local/share/updater/update.py","/.local/share/updater/updater.py","/tmp/.bun_ran","/tmp/tmp.0144018410.lock","/var/tmp/.gh_update_state"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in (HadesFiles)
      or FolderPath has_any (HadesPaths)
      or (FolderPath has "/.local/share/updater" and FileName =~ "update.py")
      or (FolderPath has "/.config/systemd/user" and FileName has_any ("update-monitor","gh-token-monitor"))
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Hades Campaign GitHub commit-search C2 with firedalazer / DontRevokeOrItGoesBoom markers

`UC_0_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(`cim_Web_indexes` (url="*api.github.com/search/commits*" OR url="*api.github.com/repos*/commits*") (url="*firedalazer*" OR url="*DontRevokeOrItGoesBoom*" OR url="*TheBeautifulSnadsOfTime*" OR src_content="*firedalazer*" OR src_content="*DontRevokeOrItGoesBoom*" OR src_content="*TheBeautifulSnadsOfTime*")) | stats count min(_time) as firstTime max(_time) as lastTime values(url) as urls values(http_method) as methods by src user dest user_agent | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.process IN ("*firedalazer*","*DontRevokeOrItGoesBoom*","*TheBeautifulSnadsOfTime*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let HadesMarkers = dynamic(["firedalazer","DontRevokeOrItGoesBoom","TheBeautifulSnadsOfTime"]);
union
(DeviceNetworkEvents
 | where Timestamp > ago(7d)
 | where RemoteUrl has "api.github.com"
 | where RemoteUrl has_any (HadesMarkers) or RemoteUrl has "search/commits"
 | where RemoteUrl has_any (HadesMarkers)
 | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Surface="network", RemoteIP, RemoteUrl,
           InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName),
(DeviceProcessEvents
 | where Timestamp > ago(7d)
 | where ProcessCommandLine has_any (HadesMarkers)
       or InitiatingProcessCommandLine has_any (HadesMarkers)
 | project Timestamp, DeviceName, AccountName, Surface="process", RemoteIP="", RemoteUrl="",
           InitiatingProcessFileName, InitiatingProcessCommandLine=strcat(InitiatingProcessCommandLine," | child=",ProcessCommandLine), InitiatingProcessParentFileName)
| order by Timestamp desc
```

### [LLM] Hades Campaign cross-platform memory scrape of GitHub Actions Runner.Worker

`UC_0_12` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python","python.exe","python3","python3.exe","powershell.exe","pwsh.exe","pwsh","bun","bun.exe") AND (Processes.process="*Runner.Worker*" OR Processes.process="*task_for_pid*" OR Processes.process="*mach_vm_read*" OR Processes.process="*ReadProcessMemory*" OR Processes.process="*VirtualQueryEx*" OR Processes.process="*/proc/*/mem*" OR Processes.process="*/proc/*/maps*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let MemPrimitives = dynamic(["Runner.Worker","task_for_pid","mach_vm_read_overwrite","vm_region_basic_info_64","ReadProcessMemory","VirtualQueryEx","PROCESS_VM_READ","/proc/","process_vm_readv"]);
let ScraperParents = dynamic(["python","python.exe","python3","python3.exe","python3.11","python3.12","powershell.exe","pwsh.exe","pwsh","bun","bun.exe"]);
let RunnerHosts =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "Runner.Worker" or FileName =~ "Runner.Worker.exe" or ProcessCommandLine has "Runner.Worker"
    | distinct DeviceId;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (RunnerHosts)
| where InitiatingProcessFileName has_any (ScraperParents) or FileName has_any (ScraperParents)
| where ProcessCommandLine has_any (MemPrimitives) or InitiatingProcessCommandLine has_any (MemPrimitives)
| where not(FileName =~ "Runner.Worker" or FileName =~ "Runner.Worker.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, FolderPath, SHA256
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

### Article-specific behavioural hunt — The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers

`UC_0_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py","_index.js","node.js","kernel32.dll","updater.py","ai_setup.sh","gh-token-monitor.sh","token-monitor.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/.bun_ran*" OR Filesystem.file_path="*/tmp/.sshu-*" OR Filesystem.file_path="*/dev/stdin*" OR Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/tmp/tmp.0144018410.lock*" OR Filesystem.file_path="*/var/tmp/.gh_update_state*" OR Filesystem.file_path="*/Library/LaunchAgents/com.user.update-monitor.plist*" OR Filesystem.file_name IN ("__init__.py","_index.js","node.js","kernel32.dll","updater.py","ai_setup.sh","gh-token-monitor.sh","token-monitor.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py", "_index.js", "node.js", "kernel32.dll", "updater.py", "ai_setup.sh", "gh-token-monitor.sh", "token-monitor.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/.bun_ran", "/tmp/.sshu-", "/dev/stdin", "/usr/bin/env", "/dev/null", "/tmp/tmp.0144018410.lock", "/var/tmp/.gh_update_state", "/Library/LaunchAgents/com.user.update-monitor.plist") or FileName in~ ("__init__.py", "_index.js", "node.js", "kernel32.dll", "updater.py", "ai_setup.sh", "gh-token-monitor.sh", "token-monitor.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
