# [HIGH] New Shai-Hulud attack trojanizes 19 science-focused PyPI packages

**Source:** BleepingComputer, StepSecurity
**Published:** 2026-06-08
**Article:** https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/

## Threat Profile

Back to Blog Threat Intel The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers, AI Analyst Misdirection, and a Wiper Deterrent Rohan Prabhu View LinkedIn June 8, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Summary On June 8, 2026, version 0.8.101 of the popular graph machine learning package ensmallen on PyPI was identified as containing a highly sophisticated supply chain compromise. Concurrent…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`
- **SHA256:** `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`
- **SHA256:** `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`

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
- **T1105** — Ingress Tool Transfer
- **T1218** — System Binary Proxy Execution
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1036.005** — Match Legitimate Name or Location
- **T1003** — OS Credential Dumping
- **T1552.001** — Unsecured Credentials: Credentials in Files
- **T1057** — Process Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.001** — Exfiltration to Code Repository
- **T1543** — Create or Modify System Process
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1053.003** — Scheduled Task/Job: Cron
- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Hades Campaign: install of trojanized scientific PyPI packages (ensmallen 0.8.101 et al.)

`UC_6_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip.exe","pip3.exe","pip","pip3","poetry.exe","poetry","uv.exe","uv","python.exe","python3.exe","python","python3")) (Processes.process="*ensmallen==0.8.101*" OR Processes.process="*ensmallen 0.8.101*" OR Processes.process="*embiggen==0.11.97*" OR Processes.process="*embiggen 0.11.97*" OR Processes.process="*gpsea==0.9.14*" OR Processes.process="*gpsea 0.9.14*" OR Processes.process="*pyphetools==0.9.120*" OR Processes.process="*pyphetools 0.9.120*" OR Processes.process="*mflux-streamlit==0.0.3*" OR Processes.process="*mflux-streamlit==0.0.4*" OR Processes.process="*nhmpy==2.4.7*" OR Processes.process="*ppkt2synergy==0.1.1*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats `summariesonly` count from datamodel=Web.Web where (Web.url="*files.pythonhosted.org*ensmallen-0.8.101*" OR Web.url="*files.pythonhosted.org*embiggen-0.11.97*" OR Web.url="*files.pythonhosted.org*gpsea-0.9.14*" OR Web.url="*files.pythonhosted.org*pyphetools-0.9.120*" OR Web.url="*mflux_streamlit-0.0.3*" OR Web.url="*mflux_streamlit-0.0.4*" OR Web.url="*nhmpy-2.4.7*" OR Web.url="*ppkt2synergy-0.1.1*") by Web.src Web.url Web.user | `drop_dm_object_name(Web)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let HadesPkgs = dynamic(["ensmallen==0.8.101","ensmallen 0.8.101","embiggen==0.11.97","embiggen 0.11.97","gpsea==0.9.14","gpsea 0.9.14","pyphetools==0.9.120","pyphetools 0.9.120","mflux-streamlit==0.0.3","mflux-streamlit==0.0.4","nhmpy==2.4.7","ppkt2synergy==0.1.1"]);
let HadesArtifacts = dynamic(["ensmallen-0.8.101","embiggen-0.11.97","gpsea-0.9.14","pyphetools-0.9.120","mflux_streamlit-0.0.3","mflux_streamlit-0.0.4","nhmpy-2.4.7","ppkt2synergy-0.1.1"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pip.exe","pip3.exe","pip","pip3","poetry.exe","poetry","uv.exe","uv","python.exe","python3.exe","python","python3") or FileName in~ ("pip.exe","pip3.exe","poetry.exe","uv.exe")
| where ProcessCommandLine has_any (HadesPkgs)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| union (DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "pythonhosted.org" or RemoteUrl has "pypi.org"
  | where RemoteUrl has_any (HadesArtifacts)
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName=InitiatingProcessFileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl)
| order by Timestamp desc
```

### [LLM] Python process downloading Bun runtime v1.3.14 ZIP from oven-sh GitHub release

`UC_6_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url IN ("*github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-linux-x64.zip*","*github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-linux-aarch64.zip*","*github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-darwin-x64.zip*","*github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-darwin-aarch64.zip*","*github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-windows-x64.zip*","*github.com/oven-sh/bun/releases/download/bun-v1.3.14/bun-windows-aarch64.zip*") by Web.src Web.dest Web.url Web.user Web.http_user_agent | `drop_dm_object_name(Web)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="b.zip" OR Filesystem.file_name="bun.zip") (Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="/tmp/*") Filesystem.process_name IN ("python.exe","python3.exe","python","python3","pythonw.exe") by Filesystem.dest Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "github.com/oven-sh/bun/releases/download/bun-v1.3.14"
| where RemoteUrl has_any ("bun-linux-x64.zip","bun-linux-aarch64.zip","bun-darwin-x64.zip","bun-darwin-aarch64.zip","bun-windows-x64.zip","bun-windows-aarch64.zip")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP
| union (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("b.zip","bun.zip") and (FolderPath has @"\Temp\" or FolderPath startswith "/tmp/" or FolderPath startswith "/var/folders/")
    | where InitiatingProcessFileName has_any ("python","pythonw")
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl=FolderPath, RemoteIP="")
| order by Timestamp desc
```

### [LLM] Bun runtime executed from /tmp/b or %TEMP%\b with Python parent (Hades Campaign loader)

`UC_6_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="bun" OR Processes.process_name="bun.exe") (Processes.process_path="*\\Temp\\b\\bun*" OR Processes.process_path="/tmp/b/bun*" OR Processes.process_path="*/var/folders/*/b/bun*") Processes.parent_process_name IN ("python.exe","python3.exe","python","python3","pythonw.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | search process="*_index.js*" OR process="*run*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bun","bun.exe")
| where (FolderPath has @"\Temp\b\" or FolderPath startswith "/tmp/b/" or FolderPath matches regex @"^/var/folders/.+/b/bun$")
| where InitiatingProcessFileName has_any ("python","pythonw")
| where ProcessCommandLine has "run" and ProcessCommandLine has "_index.js"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Process reading /proc/<pid>/mem or accessing Runner.Worker for credential scraping

`UC_6_12` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/proc/*/mem" OR Filesystem.file_path="/proc/*/maps") Filesystem.process_name IN ("python","python3","pythonw","bun","node") by Filesystem.dest Filesystem.process_name Filesystem.process Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("python","python3","pythonw","powershell.exe","pwsh.exe") (Processes.process="*task_for_pid*" OR Processes.process="*mach_vm_read*" OR Processes.process="*ReadProcessMemory*" OR Processes.process="*VirtualQueryEx*" OR Processes.process="*Runner.Worker*") by Processes.dest Processes.process_name Processes.process Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let runners = dynamic(["Runner.Worker.exe","Runner.Worker"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath startswith "/proc/" and FileName in ("mem","maps"))
| where InitiatingProcessFileName has_any ("python","bun","node")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| union (DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessParentFileName in~ (runners) or InitiatingProcessFileName in~ (runners)
    | where FileName in~ ("python.exe","python3.exe","bun.exe","powershell.exe","pwsh.exe")
    | where ProcessCommandLine has_any ("task_for_pid","mach_vm_read","ReadProcessMemory","VirtualQueryEx","OpenProcess","ctypes.CDLL","/proc/")
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName=InitiatingProcessParentFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine, FolderPath, FileName, ActionType)
| order by Timestamp desc
```

### [LLM] Hades GitHub C2 dead-drop: api.github.com commit search for magic keywords

`UC_6_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*api.github.com*" OR Web.dest="api.github.com") (Web.url="*DontRevokeOrItGoesBoom*" OR Web.url="*TheBeautifulSnadsOfTime*" OR Web.url="*firedalazer*") by Web.src Web.url Web.user Web.http_user_agent | `drop_dm_object_name(Web)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process="*DontRevokeOrItGoesBoom*" OR Processes.process="*TheBeautifulSnadsOfTime*" OR Processes.process="*firedalazer*" OR Processes.process="*search/commits*api.github.com*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let HadesKeywords = dynamic(["DontRevokeOrItGoesBoom","TheBeautifulSnadsOfTime","firedalazer"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "api.github.com"
| where RemoteUrl has_any (HadesKeywords)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP
| union (DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_any (HadesKeywords)
       or InitiatingProcessCommandLine has_any (HadesKeywords)
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl=ProcessCommandLine, RemoteIP="")
| order by Timestamp desc
```

### [LLM] Hades Campaign updater.py persistence dropper written by Bun or Python child

`UC_6_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="updater.py" Filesystem.process_name IN ("bun","bun.exe","python","python3","pythonw.exe","python.exe","node","node.exe") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_name="sc.exe" OR Processes.process_name="schtasks.exe" OR Processes.process_name="systemctl" OR Processes.process_name="launchctl" OR Processes.process_name="crontab") Processes.process="*updater.py*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "updater.py"
| where InitiatingProcessFileName has_any ("bun","python","pythonw","node")
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, FileName, SHA256, ActionType
| union (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("sc.exe","schtasks.exe","systemctl","launchctl","crontab","systemd-run")
    | where ProcessCommandLine has "updater.py"
    | project Timestamp, DeviceName, InitiatingProcessAccountName=AccountName, InitiatingProcessFileName=FileName, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessParentFileName, FolderPath, FileName, SHA256, ActionType="PersistenceRegister")
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

### Article-specific behavioural hunt — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages

`UC_6_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages ```
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
// Article-specific bespoke detection — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`, `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`, `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
