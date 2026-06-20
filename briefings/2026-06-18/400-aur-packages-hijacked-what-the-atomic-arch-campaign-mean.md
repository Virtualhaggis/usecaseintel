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
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1546.016** — Event Triggered Execution: Installer Packages
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1562.012** — Impair Defenses: Disable or Modify Linux Audit System
- **T1202** — Indirect Command Execution
- **T1204.002** — User Execution: Malicious File
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR build (makepkg/yay/paru) invokes npm|bun install of atomic-lockfile / js-digest / lockfile-js

`UC_69_3` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm","node","bun","bunx","npx","yarn") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*lockfile-js*")) AND (Processes.parent_process_name IN ("makepkg","yay","paru","pacaur","trizen","pikaur","pacman","bash","sh","zsh") OR Processes.parent_process="*PKGBUILD*" OR Processes.parent_process="*.install*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("npm","node","bun","bunx","npx","yarn")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js")
| where InitiatingProcessFileName in~ ("makepkg","bash","sh","zsh","yay","paru","pacaur","trizen","pikaur","pacman")
   or InitiatingProcessCommandLine has_any ("makepkg","PKGBUILD",".install","pacman -U","pacman -S")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Egress to Atomic Arch C2/exfil infrastructure (temp.sh, github.com/fardewoak/nodejs-argo)

`UC_69_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="temp.sh" OR All_Traffic.dest="*.temp.sh" OR All_Traffic.url="*temp.sh*" OR All_Traffic.url="*fardewoak/nodejs-argo*" OR All_Traffic.url="*fardewoak*") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.url All_Traffic.bytes_out | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count from datamodel=Web.Web where (Web.url="*temp.sh*" OR Web.url="*fardewoak/nodejs-argo*") by Web.src Web.user Web.dest Web.url Web.http_method Web.bytes_out | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
let aurParents = dynamic(["makepkg","pacman","yay","paru","pacaur","trizen","pikaur"]);
let suspiciousProcs = dynamic(["npm","node","bun","bunx","npx","curl","wget","deps"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("temp.sh","fardewoak/nodejs-argo","fardewoak")
   or RemoteUrl matches regex @"(?i)\bfardewoak\b"
| extend Suspicion = case(
    InitiatingProcessFileName in~ (suspiciousProcs), "node_or_pkg_tool",
    InitiatingProcessParentFileName in~ (aurParents), "aur_parent_chain",
    InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js"), "ioc_in_cmdline",
    "other")
| project Timestamp, DeviceName, Suspicion,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Credential file harvesting by node|npm|bun|deps reading SSH keys, browser DBs, dev tokens

`UC_69_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` values(Filesystem.file_path) as files dc(Filesystem.file_path) as DistinctCreds min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_rsa*" OR Filesystem.file_path="*/.ssh/id_ed25519*" OR Filesystem.file_path="*/.ssh/known_hosts*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.config/gh/hosts.yml*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.config/podman/auth.json*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/Cookies*" OR Filesystem.file_path="*/Login Data*" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*") AND (Filesystem.process_name IN ("node","npm","bun","bunx","npx","deps")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path | where DistinctCreds >= 3 | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let credPaths = dynamic(["/.ssh/","/.aws/credentials","/.config/gh/hosts.yml","/.npmrc","/.docker/config.json","/.config/podman/auth.json","/.kube/config","/.config/Slack/","/.config/discord","/.mozilla/firefox","/.config/google-chrome","/.config/BraveSoftware"]);
let credFiles = dynamic(["id_rsa","id_ed25519","known_hosts","credentials","hosts.yml","config.json","Cookies","Login Data",".npmrc"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened","FileAccessed","FileCreated","FileModified","FileRenamed")
| where FolderPath has_any (credPaths) or FileName in~ (credFiles)
| where InitiatingProcessFileName in~ ("node","npm","bun","bunx","npx","deps","yarn")
   or InitiatingProcessParentFileName in~ ("npm","node","bun","makepkg","yay","paru","pacman")
   or InitiatingProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js")
| summarize CredFilesAccessed = dcount(strcat(FolderPath, FileName)),
            SampleFiles = make_set(strcat(FolderPath, FileName), 25),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where CredFilesAccessed >= 3
| order by LastSeen desc
```

### eBPF rootkit load (bpftool prog/map load) from non-runtime parent post-AUR install

`UC_69_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="bpftool" AND (Processes.process="*prog load*" OR Processes.process="*prog attach*" OR Processes.process="*map create*")) AND NOT (Processes.parent_process_name IN ("systemd","systemd-bpf","containerd","dockerd","kubelet","cilium-agent","calico-node","falco","tetragon") OR Processes.parent_process_path="/usr/lib/systemd/*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let legitParents = dynamic(["systemd","systemd-bpf","containerd","dockerd","kubelet","cilium-agent","calico-node","falco","tetragon","bpfman","systemd-resolved"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "bpftool" and ProcessCommandLine has_any ("prog load","prog attach","map create","link create"))
   or ProcessCommandLine has_any ("BPF_PROG_LOAD","bpf_prog_load")
| where InitiatingProcessFileName !in~ (legitParents)
| where InitiatingProcessFolderPath !startswith "/usr/lib/systemd"
| where InitiatingProcessFolderPath !startswith "/opt/cni"
| where InitiatingProcessFolderPath !has "/cilium/" and InitiatingProcessFolderPath !has "/calico/"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentPath = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### WSL2 invoking Arch AUR helper / pacman with Atomic Arch IOC strings on Windows host

`UC_69_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("wsl.exe","wslhost.exe","wslservice.exe") OR Processes.process_name="wsl.exe") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*lockfile-js*" OR Processes.process="*yay *" OR Processes.process="*paru *" OR Processes.process="*pacaur *" OR Processes.process="*makepkg*" OR Processes.process="*pacman -S*" OR Processes.process="*pacman -U*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName in~ ("wsl.exe","wslhost.exe","wslservice.exe")
        or FileName =~ "wsl.exe")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest","lockfile-js")
     or ProcessCommandLine matches regex @"(?i)\b(yay|paru|pacaur|trizen|pikaur|makepkg)\b"
     or ProcessCommandLine has_any ("pacman -S","pacman -U","pacman -Syu")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Known Atomic Arch deps Rust ELF SHA256 on disk or in execution

`UC_69_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_hash="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let knownHashes = dynamic(["6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"]);
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (knownHashes) or InitiatingProcessSHA256 in (knownHashes)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, Source="DeviceProcessEvents"),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (knownHashes) or InitiatingProcessSHA256 in (knownHashes)
  | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessCommandLine, Source="DeviceFileEvents"),
(DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (knownHashes) or InitiatingProcessSHA256 in (knownHashes)
  | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessCommandLine, Source="DeviceImageLoadEvents")
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
