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
- **T1204.002** — User Execution: Malicious File
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1053.003** — Scheduled Task/Job: Cron
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1014** — Rootkit

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper (makepkg/pacman/yay/paru) spawns npm install of atomic-lockfile or js-digest

`UC_5_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman") Processes.process_name IN ("npm","node","npx","yarn","pnpm") (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
| where FileName in~ ("npm","node","npx","yarn","pnpm")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Credential store / SSH key / cloud-secret access by descendants of pacman or makepkg

`UC_5_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.file_name) as files values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*cookies.sqlite*" OR Filesystem.file_path="*/Login Data*") Filesystem.process_name IN ("npm","node","npx","rustc","cargo") by Filesystem.dest Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("/.ssh/","/.aws/credentials","/.npmrc","/.config/gh/","/.docker/config.json","/.config/Slack/","/.config/discord/","/.mozilla/firefox/","/.config/google-chrome/","Login Data","cookies.sqlite")
   or FileName in~ ("id_rsa","id_ed25519","id_ecdsa","known_hosts","credentials")
| where InitiatingProcessFileName in~ ("npm","node","npx","yarn","pnpm","rustc","cargo")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### Network egress from Arch build/install context to temp.sh or github.com/fardewoak/nodejs-argo

`UC_5_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_host) as hosts values(All_Traffic.dest_ip) as ips values(All_Traffic.url) as urls values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="temp.sh" OR All_Traffic.url="*github.com/fardewoak/nodejs-argo*" OR All_Traffic.url="*temp.sh*") (All_Traffic.app IN ("npm","node","npx","makepkg","pacman","yay","paru","curl","wget","rustc","cargo") OR All_Traffic.app="*") by All_Traffic.src All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("temp.sh","github.com/fardewoak/nodejs-argo")
   or RemoteUrl endswith ".temp.sh"
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman","npm","node","npx","rustc","cargo","bash","sh","curl","wget")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Persistence file writes (cron, systemd unit, shell rc) by AUR install descendants

`UC_5_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/etc/cron*" OR Filesystem.file_path="*/var/spool/cron/*" OR Filesystem.file_path="*/etc/systemd/system/*" OR Filesystem.file_path="*/usr/lib/systemd/system/*" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.zshrc" OR Filesystem.file_path="*/.config/systemd/user/*" OR Filesystem.file_path="*/sys/fs/bpf/*") (Filesystem.process_name IN ("npm","node","npx","rustc","cargo","bash","sh","makepkg","pacman","yay","paru") OR Filesystem.action="created") by Filesystem.dest Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/etc/cron.d/","/etc/cron.daily/","/etc/cron.hourly/","/var/spool/cron/","/etc/systemd/system/","/usr/lib/systemd/system/","/.bashrc","/.bash_profile","/.profile","/.zshrc","/.config/systemd/user/","/sys/fs/bpf/")
| where InitiatingProcessFileName in~ ("npm","node","npx","rustc","cargo","bash","sh","makepkg","pacman")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman","npm","node")
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest")
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

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
