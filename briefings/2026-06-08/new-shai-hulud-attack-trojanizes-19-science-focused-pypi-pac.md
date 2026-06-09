# [HIGH] New Shai-Hulud attack trojanizes 19 science-focused PyPI packages

**Source:** BleepingComputer
**Published:** 2026-06-08
**Article:** https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/

## Threat Profile

New Shai-Hulud attack trojanizes 19 science-focused PyPI packages 
By Bill Toulas 
June 8, 2026
04:41 PM
0 
Hackers compromised 19 packages on the PyPI, collectively downloaded hundreds of thousands of times, in a new Shai-Hulud supply-chain attack that delivered malware designed to steal developer secrets.
Many of the infected packages are popular bioinformatics tools such as Dynamo, Spateo, CoolBox, U-FISH, and Napari-UFISH.
The new campaign was discovered by application security company Socke…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `api.anthropic.com`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
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

### Hades Campaign: install of trojanized scientific PyPI packages (ensmallen 0.8.101 et al.)

`UC_45_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

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

### Python process downloading Bun runtime v1.3.14 ZIP from oven-sh GitHub release

`UC_45_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

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

### Bun runtime executed from /tmp/b or %TEMP%\b with Python parent (Hades Campaign loader)

`UC_45_6` · phase: **install** · confidence: **High** · AI-generated for this article

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

### Process reading /proc/<pid>/mem or accessing Runner.Worker for credential scraping

`UC_45_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

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

### Hades GitHub C2 dead-drop: api.github.com commit search for magic keywords

`UC_45_8` · phase: **c2** · confidence: **High** · AI-generated for this article

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

### Hades Campaign updater.py persistence dropper written by Bun or Python child

`UC_45_9` · phase: **install** · confidence: **High** · AI-generated for this article

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

`UC_45_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("_index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("_index.js"))
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
| where (FileName in~ ("_index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("_index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `api.anthropic.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
