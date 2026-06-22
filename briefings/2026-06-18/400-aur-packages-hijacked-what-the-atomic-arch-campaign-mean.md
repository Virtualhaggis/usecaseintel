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
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.007** — JavaScript
- **T1059.004** — Unix Shell
- **T1552.004** — Private Keys
- **T1552.001** — Credentials In Files
- **T1543.002** — Systemd Service
- **T1053.003** — Cron
- **T1546.004** — Unix Shell Configuration Modification
- **T1071.001** — Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR build pulls malicious npm/Bun dependency (atomic-lockfile / js-digest / lockfile-js)

`UC_75_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process IN ("*atomic-lockfile*","*js-digest*","*lockfile-js*")) AND (Processes.process_name IN ("npm","bun","pnpm","yarn","node","npx")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm","bun","pnpm","yarn","node","npx")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildCmd = ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Atomic Arch payload execution: JS runtime spawning shell/network tooling under AUR build (or known payload hash)

`UC_75_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.parent_process_name IN ("node","npm","npx","bun","pnpm") AND Processes.process_name IN ("sh","bash","curl","wget","nc","ncat","ssh","base64","openssl","gpg")) OR Processes.process_hash="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName in~ ("node","npm","npx","bun","pnpm")
        and FileName in~ ("sh","bash","curl","wget","nc","ncat","ssh","base64","openssl","gpg")
        and InitiatingProcessParentFileName in~ ("makepkg","fakeroot","pacman","yay","paru","bash","sh"))
    or SHA256 =~ "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
| project Timestamp, DeviceName, AccountName, InitiatingProcessIntegrityLevel,
          GrandParent = InitiatingProcessParentFileName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Atomic Arch infostealer: build-spawned process harvesting SSH keys, dev tokens and browser/Electron sessions

`UC_75_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.ssh/*","*/.npmrc","*/.docker/config.json","*/.vault-token","*/.config/gh/hosts.yml","*/.config/google-chrome/*","*/.config/BraveSoftware/*","*/.config/microsoft-edge/*","*/.config/discord/*","*/.config/Slack/*","*/.bash_history","*/.zsh_history") OR Filesystem.file_name IN ("id_rsa","id_ed25519","id_ecdsa","known_hosts","Cookies","Login Data")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","npm","bun","pnpm","npx")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","fakeroot")
| where FolderPath has_any ("/.ssh/","/.npmrc","/.docker/config.json","/.config/containers",
        "/.config/google-chrome/","/.config/BraveSoftware/","/.config/microsoft-edge/",
        "/.config/discord/","/.config/Slack/","/.config/Microsoft/Microsoft Teams","/.config/teams",
        "/.local/share/TelegramDesktop","/.vault-token","/.config/gh/hosts.yml","/.bash_history","/.zsh_history")
    or FileName in~ ("id_rsa","id_ed25519","id_ecdsa","known_hosts","Cookies","Login Data")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath
| order by Timestamp desc
```

### Atomic Arch persistence: systemd unit, cron or shell-rc written by AUR build / JS runtime

`UC_75_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/etc/systemd/system/*.service","*/.config/systemd/user/*.service","*/etc/cron.d/*","*/var/spool/cron/*","*/etc/cron.daily/*","*/etc/profile.d/*") OR Filesystem.file_name IN (".bashrc",".bash_profile",".zshrc",".profile")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName in~ ("node","npm","bun","pnpm","npx")
    or InitiatingProcessParentFileName in~ ("node","npm","bun","makepkg")
| where (FolderPath has_any ("/etc/systemd/system/","/.config/systemd/user/") and FileName endswith ".service")
    or FolderPath has_any ("/etc/cron.d/","/var/spool/cron/","/etc/cron.daily/","/etc/profile.d/")
    or FileName in~ (".bashrc",".bash_profile",".zshrc",".profile",".bash_logout")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath
| order by Timestamp desc
```

### Atomic Arch C2/exfil: build-spawned egress to temp.sh and github.com/fardewoak/nodejs-argo

`UC_75_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url IN ("*temp.sh*","*fardewoak*","*nodejs-argo*") OR Web.dest IN ("temp.sh")) by Web.src Web.user Web.url Web.dest Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","npm","bun","pnpm","npx","curl","wget","git","makepkg")
| where RemoteUrl has_any ("temp.sh","fardewoak","nodejs-argo")
    or InitiatingProcessCommandLine has_any ("temp.sh","fardewoak/nodejs-argo")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
