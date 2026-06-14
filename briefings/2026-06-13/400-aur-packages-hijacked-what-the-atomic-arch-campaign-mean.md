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
- **T1071.001** — Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1036.001** — Invalid Code Signature
- **T1027.001** — Binary Padding
- **T1554** — Compromise Host Software Binary
- **T1053.003** — Scheduled Task/Job: Cron
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR build chain spawns npm install of atomic-lockfile or js-digest (Atomic Arch execution)

`UC_9_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aurman") (Processes.process_name IN ("npm","node","npx") OR Processes.process IN ("*atomic-lockfile*","*js-digest*")) by host Processes.process_name Processes.process Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | where match(cmdline,"(?i)(atomic-lockfile|js-digest|npm\s+install)") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aurman")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru")
| where FileName in~ ("npm","node","npx","sh","bash")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
   or (ProcessCommandLine has "npm" and ProcessCommandLine has "install")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### AUR build chain egress to temp.sh or github.com/fardewoak (Atomic Arch C2/exfil)

`UC_9_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_url="*temp.sh*" OR All_Traffic.dest="temp.sh" OR All_Traffic.dest_url="*github.com/fardewoak*" OR All_Traffic.dest_url="*fardewoak/nodejs-argo*") AND All_Traffic.app IN ("npm","node","pacman","makepkg","yay","paru","curl","wget","rustc") by host All_Traffic.dest_url All_Traffic.app | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","npm","node","npx","curl","wget","bash","sh","rustc")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru")
| where RemoteUrl has_any ("temp.sh","fardewoak/nodejs-argo","github.com/fardewoak")
   or RemoteUrl endswith "temp.sh"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### eBPF program load by process descended from AUR build chain (Atomic Arch rootkit persistence)

`UC_9_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="bpftool" OR Processes.process="*BPF_PROG_LOAD*" OR Processes.process="*/sys/fs/bpf/*") Processes.user="root" by host Processes.process_name Processes.parent_process_name Processes.process Processes.user | `drop_dm_object_name(Processes)` | where match(parent,"(?i)(makepkg|pacman|yay|paru|npm|node)") | sort - lastTime
```

**Defender KQL:**
```kql
let aur_ancestors = dynamic(["makepkg","pacman","yay","paru","trizen","npm","node"]);
let ebpf_proc = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where AccountName == "root"
    | where FileName in~ ("bpftool") 
       or ProcessCommandLine has_any ("BPF_PROG_LOAD","bpf_prog_load","/sys/fs/bpf/")
    | where InitiatingProcessFileName in~ (aur_ancestors)
       or InitiatingProcessParentFileName in~ (aur_ancestors);
let ebpf_file = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath startswith "/sys/fs/bpf/"
    | where InitiatingProcessFileName in~ (aur_ancestors)
       or InitiatingProcessParentFileName in~ (aur_ancestors);
union ebpf_proc, ebpf_file
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### Non-browser process reads developer credential files post-AUR install (Atomic Arch stealer)

`UC_9_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.ssh/id_rsa","*/.ssh/id_ed25519","*/.ssh/id_ecdsa","*/.ssh/known_hosts","*/.npmrc","*/.config/gh/hosts.yml","*/.docker/config.json","*/.aws/credentials","*/.config/Slack/Cookies","*/.config/discord/Local Storage*","*/Cookies","*/Login Data")) by host Filesystem.process_name Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where NOT match(proc,"(?i)^(ssh|ssh-agent|sshd|git|gh|aws|docker|npm|chrome|firefox|brave|chromium|msedge|slack|discord|teams|gnome-keyring|seahorse|keepassxc)$") | stats values(paths) as paths_seen dc(paths) as path_count by host proc user | where path_count >= 3 | sort - path_count
```

**Defender KQL:**
```kql
let cred_paths = dynamic(["/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/known_hosts","/.npmrc","/.config/gh/hosts.yml","/.docker/config.json","/.aws/credentials","/.config/Slack/Cookies","/.config/discord/Local Storage","/Cookies","/Login Data"]);
let legit_readers = dynamic(["ssh","ssh-agent","sshd","git","gh","aws","docker","npm","chrome","firefox","brave","chromium","msedge","slack","discord","teams","gnome-keyring-daemon","keepassxc"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileOpened","FileAccessed","FileCreated")
| where FolderPath has_any (cred_paths) or FileName in~ ("Cookies","Login Data","hosts.yml","credentials","config.json",".npmrc")
| where InitiatingProcessFileName !in~ (legit_readers)
| summarize PathCount = dcount(FolderPath),
            Paths = make_set(FolderPath, 25),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessSHA256
| where PathCount >= 3
| order by PathCount desc
```

### pacman GPG signature failure or unsigned-package install during AUR build (Atomic Arch defense evasion)

`UC_9_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=linux source="/var/log/pacman.log" OR source="*pacman*"
  ("signature is unknown trust" OR "signature from" AND "is unknown" OR "PGP signature" AND "could not" OR "failed to verify" OR "invalid or corrupted package" OR "is marked as ignored" OR "--skippgpcheck" OR "--nosigs")
| rex field=_raw "installed (?<package>[^\s]+)"
| stats min(_time) as firstTime max(_time) as lastTime count values(_raw) as messages by host package
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath endswith "/var/log/pacman.log" or FolderPath endswith "/var/log/makepkg.log"
| where ActionType == "FileModified"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru")
    | where ProcessCommandLine has_any ("--skippgpcheck","--nosigs","SigLevel = Never","--noconfirm")
    | project Timestamp, DeviceName, EvasionCmd = ProcessCommandLine, EvasionParent = InitiatingProcessFileName
  ) on DeviceName
| where isnotempty(EvasionCmd)
| project Timestamp, DeviceName, EvasionParent, EvasionCmd, FolderPath
| order by Timestamp desc
```

### AUR install writes cron, systemd unit, or shell rc persistence (Atomic Arch persistence)

`UC_9_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("/etc/cron.d/*","/etc/cron.daily/*","/etc/cron.hourly/*","/etc/crontab","/var/spool/cron/*","/etc/systemd/system/*.service","/etc/systemd/system/*.timer","*/.config/systemd/user/*","*/.bashrc","*/.bash_profile","*/.zshrc","*/.profile","/etc/profile.d/*","*/.config/autostart/*")) by host Filesystem.process_name Filesystem.user Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where match(proc,"(?i)^(makepkg|pacman|yay|paru|trizen|pikaur|aurman|npm|node|sh|bash)$") | sort - lastTime
```

**Defender KQL:**
```kql
let persist_paths = dynamic(["/etc/cron.d/","/etc/cron.daily/","/etc/cron.hourly/","/etc/crontab","/var/spool/cron/","/etc/systemd/system/","/.config/systemd/user/","/.bashrc","/.bash_profile","/.zshrc","/.profile","/etc/profile.d/","/.config/autostart/"]);
let aur_chain = dynamic(["makepkg","pacman","yay","paru","trizen","pikaur","aurman","npm","node","npx"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (persist_paths) or FileName in~ (".bashrc",".zshrc",".bash_profile",".profile","crontab")
| where InitiatingProcessFileName in~ (aur_chain)
   or InitiatingProcessParentFileName in~ (aur_chain)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Parent = InitiatingProcessParentFileName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          FolderPath, FileName, SHA256
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
