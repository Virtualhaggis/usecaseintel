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
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration to Cloud Storage
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1620** — Reflective Code Loading
- **T1053.003** — Scheduled Task/Job: Cron
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR build helper (makepkg/pacman/yay) installing atomic-lockfile or js-digest npm package

`UC_7_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen") Processes.process_name IN ("npm","node","npx") (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen")
| where FileName in~ ("npm","node","npx")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### AUR build tool tree contacting temp.sh or github.com/fardewoak/nodejs-argo

`UC_7_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Web.Web where Web.url IN ("*temp.sh*","*fardewoak*","*nodejs-argo*") Web.app IN ("makepkg","pacman","yay","paru","npm","node","npx","curl","wget","git","sh","bash") by Web.dest Web.user Web.url Web.app | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node","npx","curl","wget","git","sh","bash")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru")
| where RemoteUrl has_any ("temp.sh","fardewoak","nodejs-argo")
   or RemoteUrl endswith ".temp.sh"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### npm/node child of AUR build harvesting SSH, cloud and developer credential files

`UC_7_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count dc(Filesystem.file_name) as distinct_files values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node","npm","npx") (Filesystem.file_path="*/.ssh/*" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.config/google-chrome/*Cookies*" OR Filesystem.file_path="*/.mozilla/firefox/*cookies.sqlite" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*") by Filesystem.dest Filesystem.user span=5m | `drop_dm_object_name(Filesystem)` | where distinct_files >= 3
```

**Defender KQL:**
```kql
let CredPaths = dynamic(["/.ssh/","/.npmrc","/.aws/credentials","/.docker/config.json","/.config/gh/","/.config/google-chrome/","/.mozilla/firefox/","/.config/Slack/","/.config/discord/","/.config/Code/","/.kube/config"]);
let CredNames = dynamic(["id_rsa","id_ed25519","id_ecdsa","known_hosts","cookies.sqlite","Cookies","Login Data","credentials"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileOpened")
| where (FolderPath has_any (CredPaths)) or (FileName in~ (CredNames))
| where InitiatingProcessFileName in~ ("node","npm","npx") or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru")
| summarize FilesTouched = dcount(strcat(FolderPath, FileName)), SamplePaths = make_set(strcat(FolderPath, FileName), 25), Cmd = any(InitiatingProcessCommandLine), Parent = any(InitiatingProcessParentFileName) by bin(Timestamp, 5m), DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
| where FilesTouched >= 3
| order by Timestamp desc
```

### eBPF program load (BPF_PROG_LOAD) by short-lived non-systemd parent on Arch build host

`UC_7_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.process_name IN ("bpftool","bpftrace") OR Processes.process="*BPF_PROG_LOAD*" OR Processes.process="*bpf_prog_load*" OR Processes.process="*/sys/fs/bpf/*") Processes.parent_process_name IN ("makepkg","pacman","yay","paru","npm","node","sh","bash") by Processes.dest Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bpftool","bpftrace")) or (ProcessCommandLine has_any ("BPF_PROG_LOAD","bpf_prog_load","/sys/fs/bpf/")) or (FolderPath has "/sys/fs/bpf/")
| where InitiatingProcessFileName !in~ ("systemd","systemd-networkd","systemd-resolved","containerd","dockerd","runc","kubelet","falco","cilium-agent")
| where InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
   or InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node","sh","bash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, ProcessIntegrityLevel
| order by Timestamp desc
```

### Systemd unit, timer or cron file written by AUR build / npm / node process

`UC_7_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/etc/systemd/system/*" OR Filesystem.file_path="*/usr/lib/systemd/system/*" OR Filesystem.file_path="*/etc/cron.d/*" OR Filesystem.file_path="*/var/spool/cron/*" OR Filesystem.file_path="*/etc/cron.daily/*" OR Filesystem.file_path="*/etc/cron.hourly/*" OR Filesystem.file_name="*.service" OR Filesystem.file_name="*.timer") Filesystem.process_name IN ("makepkg","pacman","yay","paru","npm","node","npx","sh","bash") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/etc/systemd/system/","/usr/lib/systemd/system/","/etc/cron.d/","/var/spool/cron/","/etc/cron.daily/","/etc/cron.hourly/","/etc/cron.weekly/")
   or FileName endswith ".service"
   or FileName endswith ".timer"
   or FileName endswith ".bashrc"
   or FileName endswith ".zshrc"
   or FileName endswith ".profile"
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node","npx","sh","bash")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### HTTPS POST/PUT upload to temp.sh from non-browser process on Arch / WSL2 host

`UC_7_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Web.http_method) as methods sum(Web.bytes_out) as bytes_out from datamodel=Web.Web where Web.url="*temp.sh*" Web.app NOT IN ("firefox","chrome","chromium","brave","msedge","opera","vivaldi") Web.http_method IN ("POST","PUT") by Web.dest Web.user Web.app Web.url | `drop_dm_object_name(Web)` | where bytes_out > 1024
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "temp.sh" or RemoteUrl endswith ".temp.sh"
| where InitiatingProcessFileName !in~ ("firefox","firefox-bin","chrome","chromium","chromium-browser","brave","brave-browser","msedge","opera","vivaldi")
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node","npx","curl","wget","sh","bash","python","python3","perl","ruby")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
