# [HIGH] Pythagora-io/gpt-pilot Compromised on GitHub - Shai-Hulud Credential Stealer Blocked by Python Linter

**Source:** StepSecurity
**Published:** 2026-06-09
**Article:** https://www.stepsecurity.io/blog/pythagora-io-gpt-pilot-compromised-on-github-shai-hulud-credential-stealer-blocked-by-python-linter

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
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1218** — Signed Binary Proxy Execution
- **T1003** — OS Credential Dumping
- **T1057** — Process Discovery
- **T1552.001** — Credentials In Files
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1554** — Compromise Client Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Python interpreter downloads oven-sh Bun runtime v1.3.14 from GitHub releases at import time

`UC_94_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where (Processes.process_name="python*" OR Processes.parent_process_name="python*") (Processes.process="*oven-sh/bun/releases/download/bun-v1.3.14*" OR Processes.process="*bun-linux-x64.zip*" OR Processes.process="*bun-linux-aarch64.zip*" OR Processes.process="*bun-darwin-x64.zip*" OR Processes.process="*bun-darwin-aarch64.zip*" OR Processes.process="*bun-windows-x64.zip*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Lookback = 14d;
// Hades Campaign import hook fetches a Bun runtime zip from oven-sh/bun releases
let NetSide = DeviceNetworkEvents
  | where Timestamp > ago(Lookback)
  | where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","pythonw.exe")
  | where RemoteUrl has "oven-sh/bun/releases/download" or RemoteUrl has "github.com/oven-sh/bun"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessFolderPath, ReportId, DeviceId;
let FileSide = DeviceFileEvents
  | where Timestamp > ago(Lookback)
  | where ActionType == "FileCreated"
  | where FileName matches regex @"^bun-(linux|darwin|windows)-(x64|aarch64)\.zip$" or FileName =~ "b.zip"
  | where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, ReportId, DeviceId;
NetSide | union FileSide
| order by Timestamp desc
```

### Bun runtime executed from temp directory by Python interpreter (Hades vF203 loader)

`UC_94_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image from datamodel=Endpoint.Processes where Processes.parent_process_name="python*" (Processes.process_name="bun" OR Processes.process_name="bun.exe") (Processes.process_path="*\\Temp\\b\\*" OR Processes.process_path="/tmp/b/*" OR Processes.process_path="/var/folders/*/b/*" OR Processes.process="*_index.js*") by host Processes.user Processes.process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","python","python3","pythonw.exe")
| where FileName in~ ("bun","bun.exe")
| where FolderPath has_any (@"\Temp\b\", @"\AppData\Local\Temp\b\", "/tmp/b/", "/var/folders/")
   or ProcessCommandLine has "_index.js"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Cross-platform memory scraping of GitHub Actions Runner.Worker process

`UC_94_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name="python*" OR Processes.parent_process_name="bun*") (Processes.process="*Runner.Worker*" OR Processes.process="*/proc/*/mem*" OR Processes.process="*/proc/*/maps*" OR Processes.process="*task_for_pid*" OR Processes.process="*vm_region_basic_info*" OR Processes.process="*mach_task_self*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// Hades Campaign Runner.Worker memory scrape — Linux /proc reads and macOS Mach VM APIs
let LinuxScrape = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where ProcessCommandLine matches regex @"/proc/\d+/(mem|maps)"
  | where InitiatingProcessFileName in~ ("python","python3","bun")
     or FileName in~ ("python","python3","bun","cat","dd","strings");
let MacScrape = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where InitiatingProcessFileName in~ ("python","python3")
  | where ProcessCommandLine has_any ("task_for_pid","vm_region_basic_info_64","mach_task_self_","vm_read_overwrite")
     or ProcessCommandLine has "Runner.Worker";
let RunnerContext = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where InitiatingProcessFileName in~ ("python","python3","bun") or InitiatingProcessParentFileName in~ ("Runner.Listener","Runner.Worker")
  | where ProcessCommandLine has "Runner.Worker";
LinuxScrape | union MacScrape | union RunnerContext
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Malicious _hooks.py / _runtime.bin files created in Pythagora gpt-pilot checkout

`UC_94_11` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.action="created" (Filesystem.file_name="_hooks.py" OR Filesystem.file_name="_runtime.bin") (Filesystem.process_name="git*" OR Filesystem.process_name="gh*" OR Filesystem.process_name="code*" OR Filesystem.process_name="cursor*" OR Filesystem.process_name="pycharm*") by host Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FileName in~ ("_hooks.py","_runtime.bin")
   or (FileName =~ "__init__.py" and FolderPath has_any ("gpt-pilot","pythagora"))
| where InitiatingProcessFileName has_any ("git.exe","git","gh.exe","gh","Code.exe","cursor.exe","pycharm64.exe","PyCharm","idea64.exe")
   or InitiatingProcessParentFileName has_any ("git.exe","git","gh.exe")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### pip / uv install of known-compromised Hades Campaign PyPI package versions

`UC_94_12` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip","pip3.exe","pip3","uv.exe","uv","poetry.exe","poetry") OR Processes.parent_process_name IN ("pip.exe","pip","pip3","uv","poetry")) (Processes.process="*ensmallen==0.8.101*" OR Processes.process="*ensmallen 0.8.101*" OR Processes.process="*mflux-streamlit==0.0.3*" OR Processes.process="*mflux-streamlit==0.0.4*" OR Processes.process="*nhmpy==2.4.7*" OR Processes.process="*ppkt2synergy==0.1.1*" OR Processes.process="*embiggen==0.11.97*" OR Processes.process="*gpsea==0.9.14*" OR Processes.process="*pyphetools==0.9.120*") by host Processes.user Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let Pkgs = dynamic(["ensmallen==0.8.101","ensmallen 0.8.101","mflux-streamlit==0.0.3","mflux-streamlit==0.0.4","nhmpy==2.4.7","ppkt2synergy==0.1.1","embiggen==0.11.97","gpsea==0.9.14","pyphetools==0.9.120"]);
let ProcSide = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName in~ ("pip.exe","pip","pip3.exe","pip3","uv.exe","uv","poetry.exe","poetry")
     or InitiatingProcessFileName in~ ("pip","pip3","pip.exe","pip3.exe","uv","poetry")
  | where ProcessCommandLine has_any (Pkgs)
  | project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath;
let FileSide = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where ActionType == "FileCreated"
  | where FolderPath has "site-packages"
  | where FolderPath matches regex @"(?i)site-packages[\\/](ensmallen|mflux[_-]streamlit|nhmpy|ppkt2synergy|embiggen|gpsea|pyphetools)([\\/-]|$)"
  | where FileName endswith ".py" or FileName endswith "METADATA" or FileName endswith "RECORD"
  | summarize FilesDropped=count(), AnyFile=any(FolderPath), FirstSeen=min(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
  | project Timestamp=FirstSeen, DeviceName, AccountName="(from-installer)", ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessCommandLine, FolderPath=AnyFile;
ProcSide | union FileSide
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

### Article-specific behavioural hunt — Pythagora-io/gpt-pilot Compromised on GitHub - Shai-Hulud Credential Stealer Blo

`UC_94_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Pythagora-io/gpt-pilot Compromised on GitHub - Shai-Hulud Credential Stealer Blo ```
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
// Article-specific bespoke detection — Pythagora-io/gpt-pilot Compromised on GitHub - Shai-Hulud Credential Stealer Blo
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

Severity classified as **HIGH** based on: 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
