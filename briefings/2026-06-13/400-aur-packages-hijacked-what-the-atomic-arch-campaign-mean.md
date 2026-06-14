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
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1548** — Abuse Elevation Control Mechanism
- **T1053.003** — Cron
- **T1037.004** — RC Scripts
- **T1547.013** — XDG Autostart Entries
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper (makepkg/yay/paru) spawning 'npm install atomic-lockfile' or 'js-digest'

`UC_9_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pamac","trizen","aura") AND Processes.process_name IN ("npm","node","npx","yarn","pnpm") AND (Processes.process LIKE "%atomic-lockfile%" OR Processes.process LIKE "%js-digest%") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pamac","trizen","aura")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pamac")
| where FileName in~ ("npm","node","npx","yarn","pnpm")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### AUR build/npm process egress to temp.sh or github.com/fardewoak/nodejs-argo

`UC_9_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest LIKE "%temp.sh%" OR All_Traffic.dest_host LIKE "%temp.sh%" OR All_Traffic.url LIKE "%temp.sh%" OR All_Traffic.url LIKE "%fardewoak/nodejs-argo%" OR All_Traffic.url LIKE "%fardewoak%") AND All_Traffic.app IN ("makepkg","pacman","yay","paru","pamac","npm","node","npx","curl","wget","sh","bash") by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.dest_host All_Traffic.url | `drop_dm_object_name(All_Traffic)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pamac","npm","node","npx","yarn","pnpm","curl","wget","sh","bash")
| where RemoteUrl has_any ("temp.sh","fardewoak/nodejs-argo","fardewoak")
   or RemoteUrl matches regex @"(?i)https?://(www\.)?temp\.sh(/|$)"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### Build-spawned process reading SSH/cloud/dev credential files within 30 min of AUR install

`UC_9_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pamac") OR (Processes.process LIKE "%atomic-lockfile%" OR Processes.process LIKE "%js-digest%" OR Processes.process LIKE "%fardewoak%") by Processes.dest Processes.user Processes.process_id Processes.process Processes._time | `drop_dm_object_name(Processes)` | rename _time as proc_start process_id as build_pid process as build_cmd | join type=inner dest [ | tstats summariesonly=t count from datamodel=Endpoint.Filesystem where (Filesystem.file_path LIKE "%/.ssh/%" OR Filesystem.file_path LIKE "%/.aws/credentials%" OR Filesystem.file_path LIKE "%/.npmrc%" OR Filesystem.file_path LIKE "%/.docker/config.json%" OR Filesystem.file_path LIKE "%/.config/gh/%" OR Filesystem.file_name IN ("id_rsa","id_ed25519","id_ecdsa","known_hosts","cookies.sqlite","Cookies","Login Data")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id Filesystem._time | `drop_dm_object_name(Filesystem)` | rename _time as read_time process_id as reader_pid ] | where read_time >= proc_start AND read_time <= proc_start + 1800 | table proc_start read_time dest build_pid build_cmd reader_pid file_path file_name
```

**Defender KQL:**
```kql
let CredPathSubstr = dynamic(["/.ssh/","/.aws/credentials","/.npmrc","/.docker/config.json","/.config/gh/","/Library/Cookies","/Cookies","/Login Data","cookies.sqlite","/known_hosts"]);
let CredFiles = dynamic(["id_rsa","id_ed25519","id_ecdsa","id_dsa","credentials","config.json","cookies.sqlite","Cookies","Login Data","known_hosts",".npmrc",".authinfo"]);
let BuildSessions = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pamac")
       or ProcessCommandLine has_any ("atomic-lockfile","js-digest","fardewoak","temp.sh")
    | project BuildStart=Timestamp, DeviceId, BuildUser=AccountName, BuildCmd=ProcessCommandLine, BuildPid=ProcessId;
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (CredPathSubstr) or FileName in~ (CredFiles)
| where InitiatingProcessFileName !in~ ("ssh","ssh-add","ssh-agent","sshd","scp","sftp","git","git-credential-helper","gpg","gnome-keyring-daemon","keyring","aws","docker","podman","chrome","chromium","firefox","brave","slack","discord","code")
| join kind=inner BuildSessions on DeviceId
| where Timestamp between (BuildStart .. BuildStart + 30m)
| project Timestamp, DeviceName, BuildUser, BuildCmd,
          ReaderProc = InitiatingProcessFileName,
          ReaderCmd = InitiatingProcessCommandLine,
          AccessedFolder = FolderPath, AccessedFile = FileName
| order by Timestamp desc
```

### eBPF program load or /sys/fs/bpf write from non-allowlisted process on Arch/dev host

`UC_9_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path LIKE "/sys/fs/bpf/%" OR Filesystem.file_path LIKE "%/bpf/%") AND NOT Filesystem.process_name IN ("systemd","systemd-networkd","systemd-resolved","calico-node","cilium-agent","cilium","bpftool","tetragon","falco","kubelet","containerd","bpfilter") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/sys/fs/bpf/" or FolderPath has "/bpf/"
| where InitiatingProcessFileName !in~ ("systemd","systemd-networkd","systemd-resolved","calico-node","cilium-agent","cilium","bpftool","tetragon","falco","kubelet","containerd","runc","crio")
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath,
          InitiatingProcessParentFileName,
          InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### AUR build-time persistence: cron/systemd/shell-init writes by makepkg or its children

`UC_9_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path LIKE "/etc/cron.%" OR Filesystem.file_path LIKE "/etc/systemd/system/%" OR Filesystem.file_path LIKE "/etc/systemd/user/%" OR Filesystem.file_path LIKE "%/.config/systemd/user/%" OR Filesystem.file_path LIKE "%/.bashrc" OR Filesystem.file_path LIKE "%/.bash_profile" OR Filesystem.file_path LIKE "%/.profile" OR Filesystem.file_path LIKE "%/.zshrc" OR Filesystem.file_path LIKE "/etc/profile.d/%" OR Filesystem.file_name LIKE "%.service" OR Filesystem.file_name LIKE "%.timer") AND (Filesystem.process_name IN ("makepkg","sh","bash","dash","node","npm","curl","wget","python","python3") AND (Filesystem.parent_process_name IN ("makepkg","pacman","yay","paru","pamac") OR Filesystem.process LIKE "%atomic-lockfile%" OR Filesystem.process LIKE "%js-digest%" OR Filesystem.process LIKE "%PKGBUILD%")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.parent_process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
let PersistPaths = dynamic(["/etc/cron.d/","/etc/cron.daily/","/etc/cron.hourly/","/etc/cron.weekly/","/var/spool/cron/","/etc/systemd/system/","/etc/systemd/user/","/.config/systemd/user/","/.bashrc","/.bash_profile","/.profile","/.zshrc","/etc/profile.d/","/.config/autostart/"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (PersistPaths)
   or FileName endswith ".service" or FileName endswith ".timer"
| where InitiatingProcessFileName in~ ("makepkg","sh","bash","dash","node","npm","npx","curl","wget","python","python3","perl")
| where InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pamac")
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest","PKGBUILD",".install","fardewoak")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          PersistPath = FolderPath, PersistFile = FileName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          Parent = InitiatingProcessParentFileName
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
