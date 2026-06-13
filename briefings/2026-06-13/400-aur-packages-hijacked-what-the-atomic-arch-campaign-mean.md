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
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration to Cloud Storage
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1543.002** — Create or Modify System Process: Systemd Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper spawning npm/bun install of atomic-lockfile or js-digest (Atomic Arch)

`UC_1_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("npm","bun","npx","pnpm","yarn","node") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm","bun","npx","pnpm","yarn","node")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          GrandparentProcess = InitiatingProcessParentFileName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildProcess = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Non-browser Linux process credential-file fan-out (atomic-lockfile 'deps' stealer)

`UC_1_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as distinct_paths values(Filesystem.file_path) as sample_paths min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.ssh/config" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.yarnrc*" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/Cookies" OR Filesystem.file_path="*/cookies.sqlite" OR Filesystem.file_path="*/.bash_history" OR Filesystem.file_path="*/.zsh_history") AND Filesystem.process_name!="chrome" AND Filesystem.process_name!="firefox" AND Filesystem.process_name!="slack" AND Filesystem.process_name!="discord" AND Filesystem.process_name!="teams" AND Filesystem.process_name!="git" AND Filesystem.process_name!="gh" AND Filesystem.process_name!="ssh" AND Filesystem.process_name!="aws" AND Filesystem.process_name!="docker" AND Filesystem.process_name!="kubectl" AND Filesystem.process_name!="vault" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | where distinct_paths >= 5 | convert ctime(firstTime) | sort - firstTime
```

**Defender KQL:**
```kql
let CredPaths = dynamic(["/.ssh/id_","/.ssh/known_hosts","/.ssh/config","/.ssh/authorized_keys","/.npmrc","/.yarnrc","/.docker/config.json","/.config/gh/hosts.yml","/.gitconfig","/.aws/credentials","/.aws/config","/.kube/config","/.vault-token","/.config/google-chrome/Default/Cookies","/.mozilla/firefox","/.config/Slack/Cookies","/.config/discord/Local Storage","/.config/Microsoft/Microsoft Teams/Cookies","/.bash_history","/.zsh_history"]);
let TrustedReaders = dynamic(["chrome","google-chrome","firefox","slack","discord","teams","code","ssh","ssh-agent","git","gh","docker","podman","kubectl","aws","vault","bash","zsh","fish","vim","nvim","emacs","less","cat","grep","systemd","gnome-keyring-daemon","tracker-miner-fs-3"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has_any (CredPaths) or strcat(FolderPath, "/", FileName) has_any (CredPaths)
| where InitiatingProcessFileName !in~ (TrustedReaders)
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen = min(Timestamp),
            DistinctPaths = dcount(strcat(FolderPath, "/", FileName)),
            SamplePaths = make_set(strcat(FolderPath, "/", FileName), 10),
            SampleCmd = any(InitiatingProcessCommandLine),
            GrandparentProcess = any(InitiatingProcessParentFileName)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessId, AccountName = InitiatingProcessAccountName
| where DistinctPaths >= 5
| order by FirstSeen desc
```

### Atomic Arch build-time C2/exfil egress to temp.sh or github.com/fardewoak

`UC_1_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(All_Traffic.dest) as remote_ips values(All_Traffic.url) as urls from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="temp.sh" OR All_Traffic.dest_host="*.temp.sh" OR All_Traffic.url="*temp.sh*" OR All_Traffic.url="*github.com/fardewoak/*" OR All_Traffic.url="*fardewoak/nodejs-argo*") AND All_Traffic.process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman","npm","bun","npx","node","cargo","rustc","curl","wget") by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.dest_host All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any ("temp.sh","fardewoak","nodejs-argo"))
     or (RemoteUrl matches regex @"github\.com/fardewoak/")
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman","npm","bun","npx","node","cargo","rustc","curl","wget")
     or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### eBPF rootkit persistence or systemd unit drop from AUR build lineage

`UC_1_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where Filesystem.action="created" AND (Filesystem.file_path="/sys/fs/bpf/*" OR Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/etc/systemd/user/*" OR Filesystem.file_path="/usr/lib/systemd/system/*") AND (Filesystem.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman") OR Filesystem.process_name IN ("npm","bun","node","npx")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.parent_process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FolderPath startswith "/sys/fs/bpf/"
     or FolderPath startswith "/etc/systemd/system"
     or FolderPath startswith "/etc/systemd/user"
     or FolderPath startswith "/usr/lib/systemd/system"
| where InitiatingProcessFileName !in~ ("systemd","systemctl","systemd-sysv-install","systemd-tmpfiles","snapd","docker","containerd","kubelet","podman","bpftool","iptables","nft","tc","cilium-agent","calico-node","falco","tracee","dpkg","rpm")
| where InitiatingProcessParentFileName has_any ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
     or InitiatingProcessFileName has_any ("npm","bun","node","npx")
     or InitiatingProcessParentFileName has_any ("npm","bun","node")
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          ActionType, FolderPath, FileName,
          InitiatingProcess = InitiatingProcessFileName,
          InitiatingCmd = InitiatingProcessCommandLine,
          ParentProcess = InitiatingProcessParentFileName
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

Severity classified as **CRIT** based on: IOCs present, 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
