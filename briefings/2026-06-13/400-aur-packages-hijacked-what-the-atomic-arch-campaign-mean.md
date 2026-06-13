# [CRIT] 400+ AUR Packages Hijacked: What the “Atomic Arch” Campaign Means for Supply-Chain Security

**Source:** StepSecurity
**Published:** 2026-06-13
**Article:** https://www.stepsecurity.io/blog/400-aur-packages-hijacked-atomic-arch-campaign

## Threat Profile

Back to Blog Threat Intel 400+ AUR Packages Hijacked: What the “Atomic Arch” Campaign Means for Supply-Chain Security On June 11th 2026, security researchers and the Arch Linux community disclosed a large-scale supply-chain attack against the Arch User Repository (AUR). Attackers hijacked more than 400 community packages and turned them into a malware delivery network. While the immediate blast radius is limited to Arch Linux systems, the campaign is a textbook example of how modern attackers co…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `temp.sh`
- **Domain (defanged):** `github.com/fardewoak/nodejs-argo`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1041** — Exfiltration Over C2 Channel
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1548** — Abuse Elevation Control Mechanism
- **T1053.003** — Scheduled Task/Job: Cron
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Atomic Arch — AUR helper spawns npm/node installing atomic-lockfile or js-digest

`UC_5_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aurman") AND Processes.process_name IN ("npm","node","npx") AND (Processes.process LIKE "%atomic-lockfile%" OR Processes.process LIKE "%js-digest%") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aurman")
| where FileName in~ ("npm","node","npx")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Atomic Arch — pacman/makepkg/npm process tree egress to temp.sh or github.com/fardewoak

`UC_5_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="temp.sh" OR All_Traffic.url LIKE "%temp.sh%" OR All_Traffic.url LIKE "%github.com/fardewoak%") AND All_Traffic.app IN ("makepkg","pacman","yay","paru","trizen","pikaur","aurman","npm","node","curl","wget","git") by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("temp.sh","fardewoak")
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aurman","npm","node","npx","curl","wget","git")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aurman")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Atomic Arch — non-browser process reading SSH, npm, docker, and cloud credential

`UC_5_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path LIKE "%/.ssh/id_%" OR Filesystem.file_path LIKE "%/.ssh/known_hosts%" OR Filesystem.file_path LIKE "%/.npmrc%" OR Filesystem.file_path LIKE "%/.docker/config.json%" OR Filesystem.file_path LIKE "%/.aws/credentials%" OR Filesystem.file_path LIKE "%/.config/gh/%" OR Filesystem.file_path LIKE "%/.config/google-chrome/%Cookies%" OR Filesystem.file_path LIKE "%/.mozilla/firefox/%cookies.sqlite%" OR Filesystem.file_path LIKE "%/.config/Slack/%" OR Filesystem.file_path LIKE "%/.config/discord/%") AND NOT Filesystem.process_name IN ("ssh","sshd","ssh-agent","scp","rsync","git","gpg","gpg-agent","npm","node","docker","aws","gh","firefox","firefox-bin","chrome","google-chrome","chromium","brave","slack","discord","teams","gnome-keyring-daemon") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/.ssh/","/.npmrc","/.docker/config.json","/.aws/credentials","/.config/gh/","/.config/google-chrome/","/.mozilla/firefox/","/.config/Slack/","/.config/discord/","/.config/Teams/")
| where ActionType in ("FileOpened","FileAccessed","FileRead","FileCreated","FileModified")
| where not (InitiatingProcessFileName in~ ("ssh","sshd","ssh-agent","ssh-keygen","scp","rsync","git","gpg","gpg-agent","npm","node","docker","aws","gh","firefox","firefox-bin","chrome","google-chrome","chromium","brave","slack","discord","teams","gnome-keyring-daemon"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### Atomic Arch — HTTPS POST/PUT exfil to temp.sh from non-browser process

`UC_5_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url LIKE "%temp.sh%" AND Web.http_method IN ("POST","PUT") AND NOT (Web.user_agent LIKE "%Mozilla%" OR Web.user_agent LIKE "%Firefox%" OR Web.user_agent LIKE "%Chrome%" OR Web.user_agent LIKE "%Safari%" OR Web.user_agent LIKE "%Edge%") by Web.src Web.user Web.url Web.http_method Web.user_agent Web.bytes_out | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "temp.sh"
| where RemoteIPType == "Public"
| where not (InitiatingProcessFileName in~ ("firefox","firefox-bin","chrome","google-chrome","chromium","brave","msedge","opera","vivaldi","safari"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Atomic Arch — eBPF program load on Arch build host (rootkit persistence)

`UC_5_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name="bpftool" OR Processes.process LIKE "%BPF_PROG_LOAD%" OR Processes.process LIKE "%/sys/fs/bpf/%") AND Processes.parent_process_name IN ("makepkg","pacman","yay","paru","npm","node","sh","bash") AND Processes.user="root" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
union
( DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where (FileName =~ "bpftool" or ProcessCommandLine has_any ("BPF_PROG_LOAD","bpf_prog_load","/sys/fs/bpf/"))
  | where InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
  | where ProcessIntegrityLevel == "System" or AccountName == "root"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
),
( DeviceFileEvents
  | where Timestamp > ago(7d)
  | where FolderPath startswith "/sys/fs/bpf/"
  | where ActionType in ("FileCreated","FileModified")
  | where InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
  | project Timestamp, DeviceName, AccountName, FileName=FileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
)
| order by Timestamp desc
```

### Atomic Arch — AUR install writes cron/systemd/shell-rc persistence on dev or CI host

`UC_5_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path LIKE "%/etc/cron%" OR Filesystem.file_path LIKE "%/etc/systemd/system/%" OR Filesystem.file_path LIKE "%/.config/systemd/user/%" OR Filesystem.file_path LIKE "%/etc/profile.d/%" OR Filesystem.file_path LIKE "%/.bashrc%" OR Filesystem.file_path LIKE "%/.zshrc%" OR Filesystem.file_path LIKE "%/.bash_profile%" OR Filesystem.file_path LIKE "%/.profile%" OR Filesystem.file_path LIKE "%/etc/crontab%" OR Filesystem.file_path LIKE "%/var/spool/cron/%") AND Filesystem.action IN ("created","modified") AND (Filesystem.process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aurman","npm","node","sh","bash") OR Filesystem.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aurman")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.parent_process_name Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/etc/cron","/etc/systemd/system/","/.config/systemd/user/","/etc/profile.d/","/.bashrc","/.zshrc","/.bash_profile","/.profile","/etc/crontab","/var/spool/cron/","/.config/autostart/")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aurman") 
    or InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node","npx")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `temp.sh`, `github.com/fardewoak/nodejs-argo`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
