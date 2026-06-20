# [CRIT] 400+ AUR Packages Hijacked: What the “Atomic Arch” Campaign Means for Supply-Chain Security

**Source:** StepSecurity
**Published:** 2026-06-18
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
- **T1059.004** — Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Credentials In Files
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1564** — Hide Artifacts
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1053.006** — Scheduled Task/Job: Systemd Timers
- **T1202** — Indirect Command Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Atomic Arch: AUR helper spawning npm/bun install of malicious lockfile packages

`UC_70_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent_name values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*lockfile-js*" OR Processes.process="*nextfile-js*" OR Processes.parent_process="*atomic-lockfile*" OR Processes.parent_process="*js-digest*" OR Processes.parent_process="*lockfile-js*" OR Processes.parent_process="*nextfile-js*") by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js","nextfile-js")
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js","nextfile-js")
| extend AurContext = iff(InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aura","pamac","npm","bun","node","npx","sh","bash"), true, false)
| project Timestamp, DeviceName, AccountName, AurContext, ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine, ChildImage=FolderPath, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Atomic Arch C2/drop egress to temp.sh or fardewoak/nodejs-argo from package install context

`UC_70_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.dest) as dest values(Web.user) as user from datamodel=Web.Web where (Web.url="*temp.sh*" OR Web.url="*fardewoak/nodejs-argo*") AND (Web.app IN ("npm","node","bun","npx","makepkg","pacman","yay","paru","pikaur","trizen","curl","wget","git")) by Web.src Web.app
| `drop_dm_object_name(Web)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where (RemoteUrl endswith "temp.sh" or RemoteUrl has "fardewoak/nodejs-argo")
| where InitiatingProcessFileName in~ ("npm","node","bun","npx","makepkg","pacman","yay","paru","pikaur","trizen","aura","pamac","curl","wget","git","sh","bash")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### Atomic Arch Linux developer-secret access by node/npm/bun stealer payload

`UC_70_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("node","npm","bun","npx")) AND (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.docker/config*" OR Filesystem.file_path="*/.config/google-chrome/*Cookies*" OR Filesystem.file_path="*/.mozilla/firefox/*cookies.sqlite*" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*" OR Filesystem.file_path="*/.config/Microsoft/Microsoft Teams/*" OR Filesystem.file_name IN ("id_rsa","id_ed25519","id_ecdsa","cookies.sqlite","key4.db","logins.json")) by Filesystem.dest Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","npm","bun","npx")
| where FolderPath has_any ("/.ssh/","/.aws/credentials","/.npmrc","/.docker/config","/.config/google-chrome/","/.mozilla/firefox/","/.config/gh/","/.config/Slack/","/.config/discord/","/.config/Microsoft/Microsoft Teams/","/.config/podman/")
   or FileName in~ ("id_rsa","id_ed25519","id_ecdsa","known_hosts","cookies.sqlite","key3.db","key4.db","logins.json","credentials",".npmrc")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### Atomic Arch eBPF rootkit BPF map pin (hidden_pids / hidden_names / hidden_inodes)

`UC_70_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_path="/sys/fs/bpf/*" AND (Filesystem.file_name IN ("hidden_pids","hidden_names","hidden_inodes")) by Filesystem.dest Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/sys/fs/bpf/"
| where FileName in~ ("hidden_pids","hidden_names","hidden_inodes")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### Atomic Arch persistence: systemd unit/timer written by node/bun/AUR-install descendant

`UC_70_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="/etc/systemd/user/*" OR Filesystem.file_path="*/.config/systemd/user/*") AND (Filesystem.file_name="*.service" OR Filesystem.file_name="*.timer") AND (Filesystem.process_name IN ("node","npm","bun","npx","makepkg","pacman","yay","paru","pikaur","trizen","aura","pamac","sh","bash")) by Filesystem.dest Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/etc/systemd/user/","/.config/systemd/user/")
| where FileName endswith ".service" or FileName endswith ".timer"
| where InitiatingProcessFileName in~ ("node","npm","bun","npx")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aura","pamac","npm","bun","node")
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName, ActionType, SHA256
| order by Timestamp desc
```

### Atomic Arch via WSL2: Windows wsl.exe invoking Arch package manager with IOC packages

`UC_70_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent_name from datamodel=Endpoint.Processes where (Processes.process_name="wsl.exe" OR Processes.parent_process_name="wsl.exe") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*lockfile-js*" OR Processes.process="*nextfile-js*" OR Processes.process="*makepkg*" OR Processes.process="*pacman -S*" OR Processes.process="*yay -S*" OR Processes.process="*paru -S*" OR Processes.process="*pikaur*") by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "wsl.exe" or InitiatingProcessFileName =~ "wsl.exe")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js","nextfile-js","makepkg","pacman -S","yay -S","paru -S","pikaur","trizen")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
