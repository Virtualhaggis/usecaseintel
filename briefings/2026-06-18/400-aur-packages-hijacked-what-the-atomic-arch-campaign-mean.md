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
- **T1071.001** — Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1105** — Ingress Tool Transfer
- **T1546.016** — Installer Packages
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1555** — Credentials from Password Stores
- **T1552.001** — Credentials In Files
- **T1195.001** — Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm install of atomic-lockfile / js-digest (Atomic Arch dropper)

`UC_70_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("npm","npx","node","pnpm","yarn") (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_name Processes.process_path | `drop_dm_object_name(Processes)` | where parent_process_name IN ("pacman","makepkg","yay","paru","pikaur","trizen","bash","sh","zsh","fish")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm","npx","node","pnpm","yarn")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          SHA256, FolderPath
| order by Timestamp desc
```

### Outbound to temp.sh from Linux dev / build host (Atomic Arch staging)

`UC_70_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*temp.sh*" OR Web.dest="temp.sh" by Web.src Web.user Web.url Web.http_user_agent Web.process Web.app | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
let dropper_parents = dynamic(["npm","node","npx","pnpm","yarn","pacman","makepkg","yay","paru","pikaur","trizen","bash","sh","zsh","curl","wget"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "temp.sh" or RemoteUrl endswith ".temp.sh"
| where InitiatingProcessFileName in~ (dropper_parents)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Access to github.com/fardewoak/nodejs-argo (Atomic Arch payload repo)

`UC_70_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*fardewoak/nodejs-argo*" OR Processes.process="*fardewoak*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where ProcessCommandLine has_any ("fardewoak/nodejs-argo","fardewoak")
  | project Timestamp, DeviceName, AccountName, EventKind="process",
            FileName, ProcessCommandLine,
            ParentProcess = InitiatingProcessFileName,
            ParentCmd = InitiatingProcessCommandLine),
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "fardewoak" or RemoteUrl has "fardewoak/nodejs-argo"
  | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
            EventKind="network", FileName = InitiatingProcessFileName,
            ProcessCommandLine = InitiatingProcessCommandLine,
            ParentProcess = InitiatingProcessParentFileName,
            ParentCmd = "")
| order by Timestamp desc
```

### AUR helper / pacman spawning npm or curl|wget|bash piping (PKGBUILD payload fetch)

`UC_70_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("pacman","makepkg","yay","paru","pikaur","trizen") (Processes.process_name IN ("npm","npx","node","pnpm","yarn") OR Processes.process="*curl*|*sh*" OR Processes.process="*wget*|*bash*" OR Processes.process="*bash -c*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pacman","makepkg","yay","paru","pikaur","trizen")
   or InitiatingProcessParentFileName in~ ("pacman","makepkg","yay","paru","pikaur","trizen")
| where (FileName in~ ("npm","npx","node","pnpm","yarn"))
     or (ProcessCommandLine has_any ("curl","wget") and ProcessCommandLine has_any ("| sh","| bash","|sh","|bash"))
     or (FileName in~ ("bash","sh","zsh") and ProcessCommandLine has "-c" and ProcessCommandLine has_any ("http://","https://"))
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildProcess = FileName, ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### eBPF program load by non-system process post-AUR-install (Atomic Arch rootkit)

`UC_70_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*bpftool*prog load*" OR Processes.process="*bpftool*prog attach*" OR Processes.process="*BPF_PROG_LOAD*" OR Processes.process_name="bpftool") Processes.user!="root" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let aur_parents = dynamic(["pacman","makepkg","yay","paru","pikaur","trizen","npm","node","npx"]);
let aur_hosts =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ (aur_parents) or InitiatingProcessFileName in~ (aur_parents)
    | summarize InstallTime = min(Timestamp) by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bpftool"
   or ProcessCommandLine has_any ("bpftool prog load","bpftool prog attach","BPF_PROG_LOAD","bpf_prog_load")
| where ProcessIntegrityLevel != "System"
| join kind=inner aur_hosts on DeviceId
| where Timestamp between (InstallTime .. InstallTime + 1h)
| project Timestamp, InstallTime, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### Mass dev-credential file access by node / npm / pacman post-install context

`UC_70_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths dc(Filesystem.file_path) as path_count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.config/gh/hosts.yml" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.config/containers/auth.json" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*" OR Filesystem.file_path="*/.config/Microsoft/Microsoft Teams/Cookies*" OR Filesystem.file_path="*/Cookies" OR Filesystem.file_path="*/Login Data" OR Filesystem.file_path="*/key4.db" OR Filesystem.file_path="*/logins.json") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where path_count >= 4
```

**Defender KQL:**
```kql
let cred_paths = dynamic([".ssh/id_",".ssh/known_hosts",".npmrc",".config/gh/hosts.yml",".aws/credentials",".config/gcloud/",".docker/config.json",".config/containers/auth.json",".config/Slack/",".config/discord/","/Cookies","/Login Data","key4.db","logins.json"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (cred_paths) or FileName has_any ("hosts.yml","credentials","config.json","auth.json","key4.db","logins.json","Cookies","Login Data")
| where InitiatingProcessFileName !in~ ("sshd","ssh","gpg-agent","keepassxc","firefox","chrome","chromium","brave","slack","discord","teams","code")
| summarize PathsTouched = dcount(FolderPath),
            Samples = make_set(FolderPath, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessAccountName,
               InitiatingProcessFileName, InitiatingProcessCommandLine,
               bin(Timestamp, 10m)
| where PathsTouched >= 4
| order by LastSeen desc
```

### Suspicious PKGBUILD modification adding download/exec primitives

`UC_70_9` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="PKGBUILD" OR Filesystem.file_name=".install" OR Filesystem.file_name=".SRCINFO" OR Filesystem.file_name="*.install") (Filesystem.action="modified" OR Filesystem.action="created" OR Filesystem.action="write") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("PKGBUILD",".SRCINFO") or FileName endswith ".install"
| where InitiatingProcessFileName !in~ ("git","vim","nvim","emacs","nano","code","vscode","makepkg","updpkgsums","namcap")
   or InitiatingProcessCommandLine has_any ("curl","wget","base64","npm install","atomic-lockfile","js-digest")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FolderPath, FileName,
          WriterProcess = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          ParentProcess = InitiatingProcessParentFileName
| order by Timestamp desc
```

### pacman post-install hook spawning network or shell utilities

`UC_70_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="pacman" OR Processes.parent_process_name="alpm") (Processes.process_name IN ("curl","wget","nc","ncat","socat","python","python3","perl","ruby") OR Processes.process="*bash -c*" OR Processes.process="*sh -c*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("pacman","alpm") 
   or InitiatingProcessParentFileName in~ ("pacman")
| where FileName in~ ("curl","wget","nc","ncat","socat","python","python3","perl","ruby")
     or (FileName in~ ("bash","sh","zsh") and ProcessCommandLine has "-c")
| where ProcessCommandLine has_any ("http://","https://","temp.sh","fardewoak","atomic-lockfile","js-digest","base64","| sh","| bash")
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildProcess = FileName, ChildCmd = ProcessCommandLine
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

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
