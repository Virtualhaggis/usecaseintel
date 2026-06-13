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
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1204.002** — User Execution: Malicious File
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1053.003** — Scheduled Task/Job: Cron
- **T1547.004** — Boot or Logon Autostart Execution: Winlogon Helper DLL
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1036.001** — Masquerading: Invalid Code Signature
- **T1027.001** — Obfuscated Files or Information: Binary Padding
- **T1553.002** — Subvert Trust Controls: Code Signing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Package manager (makepkg/pacman/yay/paru) spawning npm install of atomic-lockfile or js-digest

`UC_9_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","aurman","trizen","pamac") AND Processes.process_name IN ("npm","node","npx","pnpm","yarn") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman","trizen","pamac","bash","sh")
| where FileName in~ ("npm","node","npx","pnpm","yarn")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Non-browser process reading multiple developer credential files in rapid succession (Atomic Arch stealer)

`UC_9_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(Filesystem.file_path) as PathCount values(Filesystem.file_path) as Paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*cookies.sqlite" OR Filesystem.file_path="*Login Data" OR Filesystem.file_path="*logins.json") AND NOT Filesystem.process_name IN ("chrome","google-chrome","chromium","firefox","firefox-bin","thunderbird","slack","discord","teams","code","ssh","ssh-agent","git","gh","aws","kubectl","docker","gpg","gpg-agent","gnome-keyring-daemon") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process | where PathCount >= 3 | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredPaths = dynamic(["/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/known_hosts","/.npmrc","/.docker/config.json","/.aws/credentials","/.aws/config","/.config/gh/","/.config/gcloud/","/.kube/config","/.mozilla/firefox/","/.config/google-chrome/","/.config/chromium/","/.config/Slack/","/.config/discord/","/.config/Microsoft/Microsoft Teams/"]);
let CredFiles = dynamic(["cookies.sqlite","Login Data","Cookies","key3.db","key4.db","logins.json"]);
let Allowed = dynamic(["chrome","google-chrome","chromium","firefox","firefox-bin","thunderbird","slack","discord","teams","code","ssh","ssh-agent","git","gh","aws","kubectl","docker","gpg","gpg-agent","gnome-keyring-daemon"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileRead","FileOpened","FileCreated")
| where FolderPath has_any (CredPaths) or FileName has_any (CredFiles)
| where InitiatingProcessFileName !in~ (Allowed)
| where InitiatingProcessAccountName !endswith "$"
| summarize PathCount = dcount(strcat(FolderPath, FileName)),
            Paths = make_set(strcat(FolderPath, FileName), 50),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where PathCount >= 3
| order by LastSeen desc
```

### eBPF program load or /sys/fs/bpf object pin from AUR install context

`UC_9_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="/sys/fs/bpf/*" AND Filesystem.process_name IN ("makepkg","pacman","yay","paru","pikaur","aurman","npm","node","bash","sh") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath startswith "/sys/fs/bpf/"
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman","npm","node","bash","sh")
      or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Egress to temp.sh or github.com/fardewoak from package-manager-spawned process

`UC_9_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*temp.sh*" OR Web.url="*github.com/fardewoak*" OR Web.dest="temp.sh" OR Web.site="temp.sh") AND Web.user_agent!="Mozilla*" by Web.src Web.user Web.url Web.user_agent Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any ("temp.sh","fardewoak")) or RemoteUrl matches regex @"(?i)github\.com/fardewoak/"
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman","node","npm","curl","wget","bash","sh")
      or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman")
| project Timestamp, DeviceName,
          AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Cron, systemd unit, or shell-rc persistence written during pacman/makepkg execution

`UC_9_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/cron*" OR Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="*/.config/systemd/user/*" OR Filesystem.file_name IN (".bashrc",".bash_profile",".zshrc",".profile",".bash_login") OR Filesystem.file_path="/etc/profile.d/*" OR Filesystem.file_path="*/.config/autostart/*") AND Filesystem.process_name IN ("makepkg","pacman","yay","paru","pikaur","aurman","npm","node","bash","sh") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PersistencePaths = dynamic(["/etc/cron","/var/spool/cron","/etc/systemd/system/","/usr/lib/systemd/system/","/.config/systemd/user/","/etc/init.d/","/etc/profile.d/","/.config/autostart/","/etc/xdg/autostart/"]);
let RcFiles = dynamic([".bashrc",".bash_profile",".zshrc",".profile",".bash_login",".zprofile",".zshenv"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (PersistencePaths) or FileName in~ (RcFiles)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman","npm","node","bash","sh")
      or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","aurman")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Pacman/makepkg GPG signature failure, SigLevel=Never, or fallback to unsigned package

`UC_9_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pacman","makepkg","yay","paru","pikaur") AND (Processes.process="*SigLevel*Never*" OR Processes.process="*--nosigcheck*" OR Processes.process="*--skippgpcheck*" OR Processes.process="*--noconfirm*--nodeps*" OR Processes.process="*PACMAN_AUTH*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pacman","makepkg","yay","paru","pikaur","aurman")
| where ProcessCommandLine has_any ("--nosigcheck","--skippgpcheck","SigLevel = Never","SigLevel=Never","--noconfirm --nodeps")
      or ProcessCommandLine matches regex @"(?i)siglevel\s*=\s*(never|optional)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
