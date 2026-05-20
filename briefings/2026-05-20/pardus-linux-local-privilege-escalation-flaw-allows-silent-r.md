# [CRIT] Pardus Linux Local Privilege Escalation Flaw Allows Silent Root Access

**Source:** Cyber Security News
**Published:** 2026-05-20
**Article:** https://cybersecuritynews.com/pardus-linux-privilege-escalation-flaw/

## Threat Profile

Home Cyber Security News 
Pardus Linux Local Privilege Escalation Flaw Allows Silent Root Access 
By Abinaya 
May 20, 2026 




A critical vulnerability chain affecting Pardus Linux has been disclosed, allowing local users to gain full root privileges without authentication. 
The issue, assigned a CVSS v3.1 score of 9.3, impacts the pardus-update package, a core component responsible for system updates in the Debian-based distribution maintained by TÜBİTAK.
Pardus is widely deployed across g…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-5140`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1204.002** — User Execution: Malicious File
- **T1548.001** — Setuid and Setgid
- **T1068** — Exploitation for Privilege Escalation
- **T1059.004** — Unix Shell
- **T1548** — Abuse Elevation Control Mechanism
- **T1525** — Implant Internal Image
- **T1546** — Event Triggered Execution
- **T1195.002** — Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SUID bit set on /bin/bash via chmod (Pardus CVE-2026-5140 post-exploit)

`UC_2_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=Linux Processes.process_name=chmod (Processes.process="*4755*/bin/bash*" OR Processes.process="*4755*/bin/sh*" OR Processes.process="*4755*/bin/dash*" OR Processes.process="*u+s*/bin/bash*" OR Processes.process="*u+s*/bin/sh*" OR Processes.process="*u+s*/bin/dash*" OR Processes.process="*+s */bin/bash*") by host Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "chmod"
| where ProcessCommandLine matches regex @"(?i)chmod\s+([0-7]?[4-7][0-7]{3}|[ug]?\+s|\+s)\b.*\s/(bin|usr/bin)/(bash|sh|dash|zsh|ksh)(\s|$)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Privilege-retention root shell via '/bin/bash -p' (Pardus CVE-2026-5140 escalation)

`UC_2_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=Linux (Processes.process_name=bash OR Processes.process_name=sh OR Processes.process_name=dash) Processes.process="* -p*" by host Processes.user Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | regex process="(?i)/?(bash|sh|dash)\s+-p(\s|$)" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("bash", "sh", "dash")
| where ProcessCommandLine matches regex @"(?i)(^|/)(bash|sh|dash)\s+-p(\s|$)"
| where AccountName == "root" and InitiatingProcessAccountName != "root"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, ProcessIntegrityLevel
| order by Timestamp desc
```

### [LLM] Unprivileged pkexec invocation of pardus-update privileged actions (CVE-2026-5140 entry)

`UC_2_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os=Linux Processes.process_name=pkexec (Processes.process="*AutoAptUpgrade.py*" OR Processes.process="*SystemSettingsWrite.py*" OR Processes.process="*aptupdateaction*" OR Processes.process="*autoaptupgradeaction*" OR Processes.process="*pardus-update*") by host Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | search NOT Processes.user=root | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "pkexec"
| where ProcessCommandLine has_any ("AutoAptUpgrade.py", "SystemSettingsWrite.py", "aptupdateaction", "autoaptupgradeaction", "pardus-update")
| where InitiatingProcessAccountName != "root" and AccountName != "root"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Rogue APT source file dropped in /etc/apt/sources.list.d/ via pardus-update flow (CVE-2026-5140)

`UC_2_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_path="/etc/apt/sources.list.d/*" (Filesystem.file_name="*.list" OR Filesystem.file_name="*.sources") by host Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("apt","apt-get","aptitude","dpkg","synaptic","unattended-upgrade","add-apt-repository","software-properties-gtk") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath startswith "/etc/apt/sources.list.d/"
| where FileName endswith ".list" or FileName endswith ".sources"
| where InitiatingProcessCommandLine has_any ("AutoAptUpgrade.py", "pardus-update", "shutil.copy")
   or InitiatingProcessFileName !in~ ("apt", "apt-get", "aptitude", "dpkg", "add-apt-repository", "software-properties-gtk", "unattended-upgrade", "synaptic")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — Pardus Linux Local Privilege Escalation Flaw Allows Silent Root Access

`UC_2_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Pardus Linux Local Privilege Escalation Flaw Allows Silent Root Access ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("systemsettingswrite.py","autoaptupgrade.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/pardus/pardus-update.conf.*" OR Filesystem.file_path="*/etc/apt/sources.list.d/*" OR Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_name IN ("systemsettingswrite.py","autoaptupgrade.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Pardus Linux Local Privilege Escalation Flaw Allows Silent Root Access
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("systemsettingswrite.py", "autoaptupgrade.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/pardus/pardus-update.conf.", "/etc/apt/sources.list.d/", "/etc/shadow") or FileName in~ ("systemsettingswrite.py", "autoaptupgrade.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-5140`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
