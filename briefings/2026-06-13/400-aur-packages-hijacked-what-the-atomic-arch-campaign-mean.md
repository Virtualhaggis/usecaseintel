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
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1548** — Abuse Elevation Control Mechanism
- **T1053.003** — Scheduled Task/Job: Cron
- **T1547.004** — Boot or Logon Autostart Execution: Winlogon Helper DLL
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1543.002** — Create or Modify System Process: Systemd Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper spawning npm install of atomic-lockfile or js-digest (Atomic Arch)

`UC_2_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.process_path) as image from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aura") OR Processes.parent_process_name=".install") AND Processes.process_name IN ("npm","node","npx") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*fardewoak/nodejs-argo*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aura","sh","bash")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru")
| where FileName in~ ("npm","node","npx")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","fardewoak/nodejs-argo")
| project Timestamp, DeviceName, AccountName,
          GrandParent = InitiatingProcessParentFileName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          ChildPath = FolderPath, SHA256
| order by Timestamp desc
```

### AUR build process tree egress to temp.sh or github.com/fardewoak/nodejs-argo

`UC_2_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_url) as url values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="temp.sh" OR All_Traffic.dest_url="*temp.sh*" OR All_Traffic.dest_url="*github.com/fardewoak/nodejs-argo*" OR All_Traffic.dest_url="*github.com/fardewoak/*") AND All_Traffic.app IN ("makepkg","pacman","yay","paru","npm","node","npx","sh","bash") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aura","npm","node","npx","curl","wget")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
| where RemoteUrl has_any ("temp.sh","github.com/fardewoak/nodejs-argo")
   or RemoteUrl endswith "temp.sh"
   or RemoteUrl matches regex @"(?i)github\.com/fardewoak/"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Parent = InitiatingProcessParentFileName,
          Process = InitiatingProcessFileName,
          Cmd = InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Non-browser process reading SSH/cloud/dev-token credential files under npm/AUR build tree

`UC_2_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc values(Filesystem.process) as cmd from datamodel=Endpoint.Filesystem where Filesystem.action IN ("read","open","access") AND (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.config/containers/auth.json" OR Filesystem.file_path="*/.mozilla/firefox/*/cookies.sqlite" OR Filesystem.file_path="*/.config/google-chrome/*/Cookies" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*") AND NOT Filesystem.process_name IN ("ssh","ssh-agent","scp","sftp","git","gh","aws","docker","podman","chrome","firefox","slack","discord","keepassxc") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let CredPathFragments = dynamic(["/.ssh/id_","/.ssh/known_hosts","/.aws/credentials","/.aws/config","/.npmrc","/.config/gh/hosts.yml","/.docker/config.json","/.config/containers/auth.json","/.mozilla/firefox","/.config/google-chrome","/.config/Slack","/.config/discord","/.config/teams"]);
let ExpectedReaders = dynamic(["ssh","ssh-agent","scp","sftp","git","gh","aws","docker","podman","chrome","firefox","brave","msedge","slack","discord","teams","keepassxc","keepass","gnome-keyring","systemd"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened","FileAccessed","FileRead","FileCreated")
| extend FullPath = strcat(FolderPath, "/", FileName)
| where FullPath has_any (CredPathFragments)
| where InitiatingProcessFileName !in~ (ExpectedReaders)
| where InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","npm","node","npx","sh","bash")
   or InitiatingProcessFileName in~ ("node","npm","npx","rustc","cargo")
   or InitiatingProcessFolderPath has_any ("/tmp/","/dev/shm/","/var/tmp/")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          CredentialFile = FullPath,
          ReadingProcess = InitiatingProcessFileName,
          ReadingCmd = InitiatingProcessCommandLine,
          ReadingPath = InitiatingProcessFolderPath,
          Parent = InitiatingProcessParentFileName
| order by Timestamp desc
```

### eBPF program pinned to /sys/fs/bpf/ from non-baseline process (Atomic Arch rootkit persistence)

`UC_2_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime values(Filesystem.process_name) as proc values(Filesystem.process) as cmd values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action IN ("create","write","modify") AND Filesystem.file_path="/sys/fs/bpf/*" AND NOT Filesystem.process_name IN ("systemd","systemd-networkd","systemd-resolved","bpftool","kubelet","cilium-agent","calico-node","falco","tetragon","libbpf") by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
let LegitBpfWriters = dynamic(["systemd","systemd-networkd","systemd-resolved","bpftool","kubelet","cilium-agent","calico-node","falco","tetragon"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath startswith "/sys/fs/bpf"
| where ActionType in ("FileCreated","FileModified","FileWritten")
| where InitiatingProcessFileName !in~ (LegitBpfWriters)
| extend BpfObject = strcat(FolderPath, "/", FileName)
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("makepkg","pacman","yay","paru","npm","node")
    | project DeviceId, BuildTime=Timestamp, BuildProc=FileName, BuildCmd=ProcessCommandLine
  ) on DeviceId
| where isnotempty(BuildTime) and Timestamp between (BuildTime - 5m .. BuildTime + 30m)
| project Timestamp, DeviceName, AccountName, BpfObject,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessIntegrityLevel,
          BuildProc, BuildCmd, BuildTime
| order by Timestamp desc
```

### Persistence artifact written during AUR makepkg/pacman session (systemd/cron/shell init)

`UC_2_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_path) as paths values(Filesystem.process_name) as writer values(Filesystem.process) as cmd from datamodel=Endpoint.Filesystem where Filesystem.action IN ("create","write","modify") AND (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/etc/cron.*/*" OR Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.zshrc" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="/etc/profile.d/*") AND NOT Filesystem.process_name IN ("pacman","makepkg","dpkg","rpm","systemctl","crontab") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let PersistencePaths = dynamic(["/etc/systemd/system/","/etc/systemd/user/","/etc/cron.","/var/spool/cron/","/etc/profile.d/","/etc/rc.local","/.bashrc","/.bash_profile","/.bash_logout","/.zshrc","/.zshenv","/.profile","/.config/autostart/","/.config/systemd/user/"]);
let BuildSessions = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aura")
       or InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru")
    | summarize SessionStart=min(Timestamp), SessionEnd=max(Timestamp) by DeviceId, BuildUser=AccountName, bin(Timestamp, 30m);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileWritten")
| extend FullPath = strcat(FolderPath, "/", FileName)
| where FullPath has_any (PersistencePaths)
| where InitiatingProcessFileName !in~ ("pacman","makepkg","systemctl","crontab","systemd","useradd","dpkg","rpm")
| join kind=inner BuildSessions on DeviceId
| where Timestamp between (SessionStart .. SessionEnd + 10m)
| where AccountName == BuildUser or InitiatingProcessAccountName == "root"
| project Timestamp, DeviceName, AccountName,
          PersistenceFile = FullPath,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          Parent = InitiatingProcessParentFileName,
          BuildSessionStart = SessionStart
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

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
