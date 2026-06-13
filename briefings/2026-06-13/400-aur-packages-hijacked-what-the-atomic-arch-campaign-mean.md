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
- **T1059.004** — Unix Shell
- **T1204.002** — Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1053.003** — Scheduled Task/Job: Cron
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1547** — Boot or Logon Autostart Execution
- **T1014** — Rootkit

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Atomic Arch — npm install of atomic-lockfile/js-digest spawned by AUR build tooling

`UC_3_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.dest) as host from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("makepkg","pacman","yay","paru") OR Processes.parent_process IN ("*makepkg*","*pacman -U*","*pacman -S*","*yay -S*","*paru -S*")) AND Processes.process_name IN ("npm","node") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru")
   or InitiatingProcessCommandLine has_any ("makepkg","pacman -U","pacman -S","yay -S","paru -S")
| where FileName in~ ("npm","node") or ProcessCommandLine has "npm"
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### AUR helper (pacman/makepkg/yay/paru) spawning npm or node — anomalous for build context

`UC_3_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru") AND Processes.process_name IN ("npm","node","npx") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
let Baseline = DeviceProcessEvents
  | where Timestamp between (ago(60d) .. ago(2d))
  | where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru")
  | where FileName in~ ("npm","node","npx")
  | summarize by DeviceId, InitiatingProcessFileName, FileName;
DeviceProcessEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru")
| where FileName in~ ("npm","node","npx")
| join kind=leftanti Baseline on DeviceId, InitiatingProcessFileName, FileName
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Build-context egress to temp.sh or github.com/fardewoak/* (Atomic Arch C2/exfil)

`UC_3_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port values(All_Traffic.app) as proc from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_hostname="*temp.sh" OR All_Traffic.dest="*temp.sh*" OR All_Traffic.url="*temp.sh*" OR All_Traffic.url="*github.com/fardewoak*" OR All_Traffic.dest_hostname="github.com" AND All_Traffic.url="*fardewoak*") AND All_Traffic.app IN ("makepkg","pacman","yay","paru","npm","node","curl","wget","git") by All_Traffic.src All_Traffic.dest All_Traffic.url All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node","curl","wget","git","sh","bash")
| where RemoteUrl has_any ("temp.sh","fardewoak")
   or RemoteUrl endswith "temp.sh"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Atomic Arch stealer — non-browser process bulk-reading developer credential files

`UC_3_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as DistinctCredFiles values(Filesystem.file_path) as files values(Filesystem.process_name) as procs min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.mozilla/firefox/*cookies.sqlite" OR Filesystem.file_path="*/.config/google-chrome/*/Cookies" OR Filesystem.file_path="*/.config/Slack/*Cookies*" OR Filesystem.file_path="*/.config/discord/*") by Filesystem.dest Filesystem.user Filesystem.process_name span=5m | `drop_dm_object_name(Filesystem)` | where DistinctCredFiles >= 3 AND NOT process_name IN ("ssh","scp","sftp","git","gh","aws","docker","npm","slack","discord","firefox","chrome","chromium")
```

**Defender KQL:**
```kql
let CredFiles = dynamic(["/.ssh/id_","/.ssh/known_hosts","/.npmrc","/.config/gh/hosts.yml","/.aws/credentials","/.docker/config.json","cookies.sqlite","/.config/google-chrome/","/.config/Slack/","/.config/discord/"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened","FileCreated","FileModified")
| where FolderPath has_any (CredFiles) or FileName has_any (CredFiles)
| where InitiatingProcessFileName !in~ ("ssh","scp","sftp","git","gh","aws","docker","podman","npm","yarn","firefox","chrome","chromium","slack","discord","keyring","gnome-keyring-daemon","systemd","snapd")
| summarize DistinctCredFiles = dcount(strcat(FolderPath, FileName)),
            SampleFiles = make_set(strcat(FolderPath,"/",FileName), 25),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessSHA256, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where DistinctCredFiles >= 3
| order by FirstSeen desc
```

### systemd unit or cron entry written inside pacman/makepkg execution context

`UC_3_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/etc/cron.d/*" OR Filesystem.file_path="/etc/cron.hourly/*" OR Filesystem.file_path="/etc/cron.daily/*" OR Filesystem.file_path="/etc/cron.weekly/*" OR Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="*/.config/systemd/user/*") AND Filesystem.process_name IN ("makepkg","pacman","yay","paru","npm","node","sh","bash") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/etc/systemd/system/","/etc/cron.d/","/etc/cron.hourly/","/etc/cron.daily/","/etc/cron.weekly/","/etc/cron.monthly/","/var/spool/cron/","/.config/systemd/user/")
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru")
   or InitiatingProcessCommandLine has_any ("makepkg","pacman -U","pacman -S","yay -S","paru -S")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Pinned eBPF object created on Linux endpoint by non-baseline process

`UC_3_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc values(Filesystem.process_path) as proc_path from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND Filesystem.file_path="/sys/fs/bpf/*" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("systemd","bpftool","mdatp","falcon-sensor","crowdstrike","cilium-agent","calico-node","tetragon") | convert ctime(firstTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath startswith "/sys/fs/bpf/"
| where InitiatingProcessFileName !in~ ("systemd","bpftool","mdatp","wdavdaemon","falcon-sensor","falconctl","cilium-agent","calico-node","tetragon","systemd-networkd")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessSHA256, InitiatingProcessParentFileName
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
