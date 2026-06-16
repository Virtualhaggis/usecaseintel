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
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1053.003** — Scheduled Task/Job: Cron
- **T1547.013** — Boot or Logon Autostart Execution: XDG Autostart Entries

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper or makepkg spawning npm/node to install atomic-lockfile or js-digest

`UC_52_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.user) as user values(Processes.process_path) as image from datamodel=Endpoint.Processes where Processes.process_name IN ("npm","node") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") AND Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aura") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("npm","node")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aura","bash","sh","fakeroot")
   or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aura")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Grandparent = InitiatingProcessParentFileName,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### AUR build process egress to temp.sh or github.com/fardewoak/nodejs-argo

`UC_52_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aura","npm","node","bash","sh") AND (Processes.process="*temp.sh*" OR Processes.process="*fardewoak*" OR Processes.process="*nodejs-argo*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)`) | append [| tstats summariesonly=t count from datamodel=Network_Resolution.DNS where (DNS.query="temp.sh" OR DNS.query="*.temp.sh") by DNS.src DNS.query DNS.process_name | `drop_dm_object_name(DNS)` | search process_name IN ("makepkg","pacman","yay","paru","npm","node","curl","wget","git")]
```

**Defender KQL:**
```kql
let buildParents = dynamic(["makepkg","pacman","yay","paru","trizen","pikaur","aura","npm","node","bash","sh","fakeroot"]);
union
( DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where InitiatingProcessFileName in~ (buildParents) or InitiatingProcessParentFileName in~ (buildParents)
  | where ProcessCommandLine has_any ("temp.sh","fardewoak","nodejs-argo")
  | project Timestamp, DeviceName, AccountName, Source="ProcessCmdline",
            Initiator = InitiatingProcessFileName,
            ChildBin = FileName,
            Detail = ProcessCommandLine
),
( DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where InitiatingProcessFileName in~ (buildParents)
  | where RemoteUrl has_any ("temp.sh","fardewoak","nodejs-argo")
  | project Timestamp, DeviceName, AccountName, Source="NetworkEvent",
            Initiator = InitiatingProcessFileName,
            ChildBin = "",
            Detail = strcat(RemoteUrl, " (", tostring(RemoteIP), ":", tostring(RemotePort), ")")
)
| order by Timestamp desc
```

### Non-browser process fan-out reading SSH/npm/Docker/AWS/browser credential stores on Arch host

`UC_52_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Filesystem.file_path) as files dc(Filesystem.file_path) as distinct_files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*Cookies*" OR Filesystem.file_path="*cookies.sqlite*" OR Filesystem.file_path="*key4.db*" OR Filesystem.file_path="*Login Data*" OR Filesystem.file_path="*/.config/Slack/storage*" OR Filesystem.file_path="*/.config/discord*") AND Filesystem.process_name!="ssh" AND Filesystem.process_name!="scp" AND Filesystem.process_name!="sftp" AND Filesystem.process_name!="git" AND Filesystem.process_name!="firefox" AND Filesystem.process_name!="chrome" AND Filesystem.process_name!="chromium" AND Filesystem.process_name!="slack" AND Filesystem.process_name!="discord" AND Filesystem.process_name!="gh" AND Filesystem.process_name!="aws" AND Filesystem.process_name!="npm" AND Filesystem.process_name!="docker" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path _time span=2m | `drop_dm_object_name(Filesystem)` | where distinct_files >= 4 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredPaths = dynamic(["/.ssh/id_","/.ssh/known_hosts","/.npmrc","/.docker/config.json","/.aws/credentials","/.aws/config","/.config/gh/hosts.yml","/.config/glab-cli","Cookies","cookies.sqlite","key4.db","Login Data","/.config/Slack/storage","/.config/discord","/.config/Teams","/.kube/config","/.vault-token"]);
let KnownGood = dynamic(["ssh","scp","sftp","git","ssh-agent","gpg","gpg-agent","firefox","chrome","google-chrome","chromium","brave-browser","slack","discord","teams","code","gh","glab","aws","docker","npm","kubectl","vault","gnome-keyring-daemon","keepassxc","keyring","snap"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpen","FileRead","FileCreated","FileModified")
| where FolderPath has_any (CredPaths) or FileName in~ ("Cookies","cookies.sqlite","key4.db","Login Data",".vault-token")
| where InitiatingProcessFileName !in~ (KnownGood)
| summarize DistinctTargets = dcount(FolderPath),
            Targets = make_set(FolderPath, 25),
            First = min(Timestamp), Last = max(Timestamp),
            Reads = count()
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath, bin(Timestamp, 2m)
| where DistinctTargets >= 4
| order by Last desc
```

### eBPF program load or pinned object created from non-system parent on Arch host

`UC_52_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_path) as image values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="/sys/fs/bpf/*" AND Filesystem.action IN ("created","modified") AND Filesystem.process_name!="systemd" AND Filesystem.process_name!="systemd-networkd" AND Filesystem.process_name!="bpftool" AND Filesystem.process_name!="cilium-agent" AND Filesystem.process_name!="tetragon" AND Filesystem.process_name!="falco" AND Filesystem.process_name!="tracee" AND Filesystem.process_name!="containerd" AND Filesystem.process_name!="runc" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let KnownEbpfConsumers = dynamic(["systemd","systemd-networkd","systemd-resolved","bpftool","cilium-agent","cilium","tetragon","falco","tracee","sysdig","containerd","runc","crun","docker","dockerd","kubelet","calico-node","snap","mdatp","falcon-sensor","perf","bpftrace"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath startswith "/sys/fs/bpf/"
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName !in~ (KnownEbpfConsumers)
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("makepkg","pacman","yay","paru")
    | project AurTime=Timestamp, DeviceId, AurFile=FileName, AurCmd=ProcessCommandLine
  ) on DeviceId
| extend BuildContextNearby = iif(isnotempty(AurTime) and Timestamp between (AurTime .. AurTime + 1h), true, false)
| project Timestamp, DeviceName, AccountName,
          BpfObject = FolderPath,
          BpfFile = FileName,
          Initiator = InitiatingProcessFileName,
          InitiatorCmd = InitiatingProcessCommandLine,
          InitiatorParent = InitiatingProcessParentFileName,
          BuildContextNearby, AurFile, AurCmd
| order by Timestamp desc
```

### Persistence written to user shell init or systemd user units from AUR build/install scriptlet

`UC_52_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process) as cmd values(Filesystem.process_path) as image from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.zshrc" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.bash_aliases" OR Filesystem.file_path="*/.config/systemd/user/*" OR Filesystem.file_path="*/.config/autostart/*" OR Filesystem.file_path="/etc/cron.d/*" OR Filesystem.file_path="/etc/cron.daily/*" OR Filesystem.file_path="/etc/cron.hourly/*" OR Filesystem.file_path="/var/spool/cron/*" OR Filesystem.file_path="/etc/profile.d/*" OR Filesystem.file_path="/etc/ld.so.preload") AND (Filesystem.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aura") OR Filesystem.process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aura")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.parent_process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let PersistencePaths = dynamic(["/.bashrc","/.bash_profile","/.zshrc","/.profile","/.bash_aliases","/.zprofile","/.config/systemd/user/","/.config/autostart/","/etc/cron.d/","/etc/cron.daily/","/etc/cron.hourly/","/var/spool/cron/","/etc/profile.d/","/etc/ld.so.preload","/etc/systemd/system/"]);
let AurTools = dynamic(["makepkg","pacman","yay","paru","trizen","pikaur","aura","fakeroot"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (PersistencePaths) or FileName in~ (".bashrc",".zshrc",".profile","ld.so.preload")
| where InitiatingProcessFileName in~ (AurTools)
   or InitiatingProcessParentFileName in~ (AurTools)
   or InitiatingProcessCommandLine has_any ("PKGBUILD",".install","post_install","pre_install","makepkg")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          WriterParent = InitiatingProcessParentFileName,
          PersistenceFile = strcat(FolderPath, "/", FileName),
          SHA256
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
