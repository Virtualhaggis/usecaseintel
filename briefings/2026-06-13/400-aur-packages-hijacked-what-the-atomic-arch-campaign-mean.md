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
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1204.002** — User Execution: Malicious File
- **T1554** — Compromise Host Software Binary
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1041** — Exfiltration Over C2 Channel
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1199** — Trusted Relationship
- **T1053.003** — Scheduled Task/Job: Cron
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries
- **T1037.004** — Boot or Logon Initialization Scripts: RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### makepkg/pacman/yay/paru spawning npm or node during AUR build

`UC_8_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen") (Processes.process_name IN ("npm","node","npx","pnpm","yarn") OR Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by host Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen")
| where FileName in~ ("npm","node","npx","pnpm","yarn")
   or ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### npm install of atomic-lockfile or js-digest package

`UC_8_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by host Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine
| order by Timestamp desc
```

### PKGBUILD or .install file modified to add npm/curl/wget network primitive

`UC_8_5` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where (Filesystem.file_name="PKGBUILD" OR Filesystem.file_name="*.install") Filesystem.action IN ("created","modified") by host Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "PKGBUILD" or FileName endswith ".install"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("makepkg","pacman","git","git-remote-https")
   or InitiatingProcessCommandLine has_any ("npm ","curl ","wget ","fetch ")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### DNS or HTTP egress to github.com/fardewoak or temp.sh from package-build process

`UC_8_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="temp.sh" OR All_Traffic.dest="*.temp.sh" OR All_Traffic.url="*fardewoak/nodejs-argo*") All_Traffic.app IN ("makepkg","pacman","yay","paru","npm","node","curl","wget") by host All_Traffic.src All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("temp.sh","fardewoak/nodejs-argo","github.com/fardewoak")
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","npm","node","npx","curl","wget","git")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

### Non-browser process reads ~/.ssh, ~/.aws, ~/.docker or browser cookie DB on Arch host

`UC_8_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/cookies.sqlite" OR Filesystem.file_path="*/Cookies" OR Filesystem.file_path="*/.config/Slack/Cookies*" OR Filesystem.file_path="*/.config/discord/*Cookies*") Filesystem.action="read" Filesystem.process_name!="chrome" Filesystem.process_name!="firefox" Filesystem.process_name!="firefox-bin" Filesystem.process_name!="slack" Filesystem.process_name!="discord" Filesystem.process_name!="Teams" by host Filesystem.user Filesystem.process_name | where mvcount(paths) >= 3 | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredPaths = dynamic(["/.ssh/id_","/.ssh/known_hosts","/.aws/credentials","/.docker/config.json","/.npmrc","/.config/gh/","cookies.sqlite","/Cookies","/.config/Slack/","/.config/discord/","/.config/teams/"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened","FileAccessed","FileRead")
| where FolderPath has_any (CredPaths)
| where InitiatingProcessFileName !in~ ("chrome","firefox","firefox-bin","brave","slack","discord","teams","gh","ssh","git","aws","docker","podman","npm")
| where InitiatingProcessAccountName !endswith "$"
| summarize PathCount = dcount(FolderPath), Paths = make_set(FolderPath, 20), FirstSeen = min(Timestamp)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| where PathCount >= 3
| order by FirstSeen desc
```

### Outbound HTTPS upload to temp.sh from build/CI host with non-browser user agent

`UC_8_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.http_method) as methods values(Web.bytes_out) as bytes_out values(Web.http_user_agent) as ua from datamodel=Web.Web where Web.dest="temp.sh" Web.http_method IN ("POST","PUT") by host Web.src Web.app | search NOT (ua IN ("*Chrome*","*Firefox*","*Safari*","*Edge*")) | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "temp.sh"
| where InitiatingProcessFileName !in~ ("chrome","firefox","firefox-bin","brave","msedge","safari")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### bpf() syscall or BPF program load by package-manager process tree

`UC_8_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process="*bpf_prog_load*" OR Processes.process="*bpftool prog load*" OR Processes.process="*BPF_PROG_LOAD*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BuildAncestors = DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","npm","node")
    | project SuspectProcessId = ProcessId, SuspectStart = Timestamp, DeviceId;
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath startswith "/sys/fs/bpf/" and ActionType in ("FileCreated","FileModified")
| join kind=inner (BuildAncestors) on DeviceId
| where Timestamp between (SuspectStart .. SuspectStart + 1h)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

### AUR package install after maintainer ownership transfer to attacker-tied account

`UC_8_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("pacman","yay","paru","makepkg") (Processes.process="*-S *" OR Processes.process="*-U *" OR Processes.process="*--sync*") by host Processes.user Processes.process | lookup aur_attacker_packages package_name AS process OUTPUT maintainer adoption_date | where isnotnull(maintainer) | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let AttackerMaintainers = dynamic(["krisztinavarga","custodiatovar","veramagalhaes","herbsobering"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pacman","yay","paru","pikaur","trizen","makepkg")
   or FileName in~ ("pacman","yay","paru","makepkg")
| where ProcessCommandLine has_any (" -S ", " -U ", "--sync", "-Syu", "--install")
   or InitiatingProcessCommandLine has_any (AttackerMaintainers)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### AUR install hook writes cron, systemd unit or shell rc file

`UC_8_11` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/cron.*" OR Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="/etc/systemd/system/*.service" OR Filesystem.file_path="/etc/systemd/system/*.timer" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.zshrc" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.config/autostart/*") (Filesystem.process_name="pacman" OR Filesystem.process_name="makepkg" OR Filesystem.process_name="sh" OR Filesystem.process_name="bash") by host Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let PersistencePaths = dynamic(["/etc/cron.d/","/etc/cron.daily/","/etc/cron.hourly/","/var/spool/cron/","/etc/systemd/system/","/.config/systemd/user/","/.bashrc","/.zshrc","/.profile","/.bash_profile","/.config/autostart/"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (PersistencePaths)
| where InitiatingProcessFileName in~ ("pacman","makepkg","sh","bash","yay","paru")
   or InitiatingProcessParentFileName in~ ("pacman","makepkg","yay","paru")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
