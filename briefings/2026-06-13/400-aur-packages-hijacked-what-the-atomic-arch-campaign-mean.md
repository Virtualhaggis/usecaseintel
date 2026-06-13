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
- **T1059.007** — JavaScript
- **T1204.002** — Malicious File
- **T1059.004** — Unix Shell
- **T1552.001** — Credentials In Files
- **T1552.004** — Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1548** — Abuse Elevation Control Mechanism
- **T1071.001** — Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration to Cloud Storage
- **T1053.003** — Cron
- **T1547.013** — XDG Autostart Entries
- **T1037.004** — RC Scripts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper / makepkg spawns npm install of atomic-lockfile or js-digest

`UC_8_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","aurman","pamac") AND Processes.process_name IN ("npm","npx","node","pnpm","yarn") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by host Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","aurman","pamac")
| where FileName in~ ("npm","npx","node","pnpm","yarn")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PKGBUILD .install lifecycle hook spawns network-fetch utility

`UC_8_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("bash","sh","makepkg") AND (Processes.parent_process="*.install*" OR Processes.parent_process="*PKGBUILD*" OR Processes.parent_process="*.pacman-*") AND Processes.process_name IN ("curl","wget","node","npm","npx","python","python3","perl") AND (Processes.process="*http*" OR Processes.process="*temp.sh*" OR Processes.process="*fardewoak*") by host Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let FetchBins = dynamic(["curl","wget","node","npm","npx","python","python3","perl"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("bash","sh","makepkg")
| where InitiatingProcessCommandLine has_any (".install","PKGBUILD",".pacman-",".SRCINFO")
| where FileName in~ (FetchBins)
| where ProcessCommandLine has_any ("https://","http://","ssh://","git://","temp.sh","github.com/fardewoak","raw.githubusercontent.com")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Credential-store access by process descended from AUR makepkg / npm build chain

`UC_8_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts*" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_name IN ("Cookies","Login Data","key4.db","logins.json")) AND Filesystem.process_name IN ("npm","node","npx","makepkg","pacman","yay","paru") by host Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredPathFragments = dynamic([@"/.ssh/id_", @"/.ssh/known_hosts", @"/.ssh/config", @"/.config/gh/", @"/.npmrc", @"/.docker/config.json", @"/.aws/credentials", @"/.kube/config", @"/.config/Slack/", @"/.config/discord/", @"/.mozilla/firefox/"]);
let CredFileNames = dynamic(["Cookies","Login Data","key4.db","logins.json","credentials.json","cookies.sqlite"]);
let TrustedReaders = dynamic(["chrome","firefox","brave","msedge","opera","slack","discord","teams","sshd","ssh","openssh","gnome-keyring","seahorse","keepassxc"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileAccessed","FileOpened","FileRead","FileCreated")
| where FolderPath has_any (CredPathFragments) or FileName in~ (CredFileNames)
| where not (InitiatingProcessFileName in~ (TrustedReaders))
| where InitiatingProcessFileName in~ ("npm","node","npx","makepkg","pacman","yay","paru")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
    or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

### eBPF rootkit object created from AUR-install descendant on non-CNI host

`UC_8_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/sys/fs/bpf/*" OR Filesystem.file_path="*/bpf/*" OR Filesystem.file_name="*.bpf.o") AND Filesystem.process_name IN ("npm","node","npx","makepkg","pacman","yay","paru","bash","sh","rustc","cargo") AND NOT Filesystem.process_name IN ("kubelet","containerd","cilium-agent","calico-node","falco","tetragon","datadog-agent","crio") by host Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CniHostMarkers = dynamic(["kubelet","containerd","cilium-agent","calico-node","falco","tetragon","datadog-agent","crio","bpftrace","bpftool"]);
let BuildChain = dynamic(["npm","node","npx","makepkg","pacman","yay","paru","bash","sh","rustc","cargo"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath startswith "/sys/fs/bpf/" or FolderPath has "/bpf/" or FileName endswith ".bpf.o"
| where not (InitiatingProcessFileName in~ (CniHostMarkers))
| where InitiatingProcessFileName in~ (BuildChain)
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
    or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

### Egress to temp.sh or github.com/fardewoak/* from AUR build-chain process

`UC_8_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*temp.sh*" OR Web.url="*github.com/fardewoak*" OR Web.url="*fardewoak/nodejs-argo*" OR Web.dest="temp.sh") AND Web.user_agent!="*Mozilla*" by host Web.user Web.app Web.url Web.dest Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("temp.sh","github.com/fardewoak","fardewoak/nodejs-argo")
| where InitiatingProcessFileName in~ ("npm","node","npx","makepkg","pacman","yay","paru","curl","wget","bash","sh","rustc","cargo")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Cron / systemd persistence written by AUR build-chain descendant

`UC_8_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/cron*" OR Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/usr/lib/systemd/system/*" OR Filesystem.file_path="*/.config/systemd/user/*" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.zshrc") AND Filesystem.process_name IN ("npm","node","npx","makepkg","pacman","yay","paru","bash","sh","python","python3") AND NOT Filesystem.process_name IN ("dpkg","rpm","systemd-tmpfiles","systemctl","cron","crond","systemd") by host Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let PersistencePaths = dynamic([@"/etc/cron.d/",@"/etc/cron.hourly/",@"/etc/cron.daily/",@"/etc/cron.weekly/",@"/etc/cron.monthly/",@"/var/spool/cron/",@"/etc/systemd/system/",@"/usr/lib/systemd/system/",@"/.config/systemd/user/",@"/.config/autostart/"]);
let RcFiles = dynamic([".bashrc",".bash_profile",".profile",".zshrc",".zshenv",".xinitrc"]);
let TrustedInstallers = dynamic(["dpkg","rpm","systemd-tmpfiles","systemctl","cron","crond","systemd","apt","apt-get","dnf","yum"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (PersistencePaths) or FileName in~ (RcFiles)
| where not (InitiatingProcessFileName in~ (TrustedInstallers))
| where InitiatingProcessFileName in~ ("npm","node","npx","makepkg","pacman","yay","paru","bash","sh","python","python3")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","npm","node")
    or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FolderPath, FileName
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
