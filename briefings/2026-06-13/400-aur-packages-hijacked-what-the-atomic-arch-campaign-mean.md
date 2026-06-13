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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1014** — Rootkit
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1053.003** — Scheduled Task/Job: Cron
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1657** — Financial Theft (use of stolen tokens)
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR package manager spawning npm install of atomic-lockfile or js-digest

`UC_3_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman") Processes.process_name IN ("npm","node","npx") (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
| where FileName in~ ("npm","node","npx")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Grandparent = InitiatingProcessParentFileName,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256, FolderPath
| order by Timestamp desc
```

### Build process outbound to Atomic Arch C2 (temp.sh or fardewoak GitHub)

`UC_3_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("npm","node","npx","curl","wget","makepkg","pacman","yay","paru") (All_Traffic.dest IN ("temp.sh","*.temp.sh") OR All_Traffic.url="*temp.sh*" OR All_Traffic.url="*fardewoak/nodejs-argo*" OR All_Traffic.url="*fardewoak*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.url All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("npm","node","npx","makepkg","pacman","yay","paru","pikaur","curl","wget")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
| where RemoteUrl has_any ("temp.sh","fardewoak/nodejs-argo","fardewoak")
    or RemoteUrl matches regex @"(?i)(^|\.)temp\.sh($|/|:)"
| project Timestamp, DeviceName, AccountDomain = InitiatingProcessAccountDomain, AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort, Protocol, ActionType
| order by Timestamp desc
```

### Build-spawned node process reading multiple developer credential files on Arch host

`UC_3_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths dc(Filesystem.file_path) as path_count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*" OR Filesystem.file_path="*/Cookies*" OR Filesystem.file_path="*/Login Data*") (Filesystem.process_name IN ("node","npm","npx") OR Filesystem.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.parent_process_name
| `drop_dm_object_name(Filesystem)`
| where path_count >= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredentialPaths = dynamic(["/.ssh/id_","/.ssh/known_hosts","/.aws/credentials","/.docker/config.json","/.npmrc","/.config/gh","/.config/Slack","/.config/discord","/.config/Code","/.mozilla/firefox","/Cookies","/Login Data"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","npm","npx")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
| extend MatchedPath = tostring(array_iff(CredentialPaths, true))
| where FolderPath has_any (CredentialPaths) or FileName has_any ("id_rsa","id_ed25519","id_ecdsa","known_hosts","credentials","config.json")
| summarize CredCategoriesTouched = dcount(case(
        FolderPath has "/.ssh/", "ssh",
        FolderPath has "/.aws/", "aws",
        FolderPath has "/.docker/", "docker",
        FolderPath has "/.npmrc", "npm",
        FolderPath has "/.config/gh", "github",
        FolderPath has "/.config/Slack", "slack",
        FolderPath has "/.config/discord", "discord",
        FolderPath has_any ("Cookies","Login Data","/.mozilla/"), "browser",
        "other")),
    FileSample = make_set(strcat(FolderPath, "/", FileName), 25),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp), TotalAccesses = count()
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| where CredCategoriesTouched >= 3
| order by LastSeen desc
```

### AUR build context writing eBPF objects, systemd units, or cron entries

`UC_3_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/sys/fs/bpf/*" OR Filesystem.file_path="/etc/systemd/system/*" OR Filesystem.file_path="/etc/cron.d/*" OR Filesystem.file_path="/etc/cron.hourly/*" OR Filesystem.file_path="*/.bashrc" OR Filesystem.file_path="*/.bash_profile" OR Filesystem.file_path="*/.profile" OR Filesystem.file_path="*/.config/systemd/user/*") (Filesystem.process_name IN ("node","npm","npx","bpftool","rustc") OR Filesystem.parent_process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.parent_process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath startswith "/sys/fs/bpf/"
    or FolderPath startswith "/etc/systemd/system/"
    or FolderPath startswith "/etc/cron.d/"
    or FolderPath startswith "/etc/cron.hourly/"
    or FolderPath startswith "/etc/cron.daily/"
    or FolderPath has "/.config/systemd/user/"
    or (FileName in~ (".bashrc",".bash_profile",".profile",".zshrc") and FolderPath !startswith "/etc/skel")
| where InitiatingProcessFileName in~ ("node","npm","npx","bpftool")
    or InitiatingProcessParentFileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
| where InitiatingProcessAccountName != "root" or InitiatingProcessParentFileName in~ ("makepkg","yay","paru")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          ActionType, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### GitHub or cloud SSO sign-in from new ASN by developer whose host recently ran AUR install

`UC_3_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as aur_first max(_time) as aur_last values(Processes.dest) as aur_hosts from datamodel=Endpoint.Processes where Processes.process_name IN ("makepkg","pacman","yay","paru","pikaur","trizen","aurman") by Processes.user
| `drop_dm_object_name(Processes)`
| rename user as src_user
| join type=inner src_user [
    | tstats `summariesonly` count min(_time) as auth_first max(_time) as auth_last values(Authentication.src) as auth_ips values(Authentication.app) as apps dc(Authentication.src) as ip_count from datamodel=Authentication where Authentication.action="success" Authentication.app IN ("GitHub","AzureAD","AWS Management Console","npm","Google") by Authentication.user
    | `drop_dm_object_name(Authentication)`
    | rename user as src_user
]
| where auth_last >= aur_first and ip_count > 1
| `security_content_ctime(aur_first)`
| `security_content_ctime(auth_last)`
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let AurUsers = DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName in~ ("makepkg","pacman","yay","paru","pikaur","trizen","aurman")
    | where isnotempty(AccountUpn)
    | summarize AurFirst = min(Timestamp), AurLast = max(Timestamp), AurHosts = make_set(DeviceName, 20) by AccountUpn;
let KnownIps = AADSignInEventsBeta
    | where Timestamp between (ago(60d) .. ago(LookbackDays))
    | summarize by AccountUpn, IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(LookbackDays)
| where ErrorCode == 0
| join kind=inner AurUsers on AccountUpn
| where Timestamp >= AurFirst
| join kind=leftanti KnownIps on AccountUpn, IPAddress
| where Application has_any ("GitHub","npm","Amazon","AWS","GitLab","Docker","Vault") or ResourceDisplayName has_any ("GitHub","npm","AWS","GitLab","Docker","Vault")
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ResourceDisplayName, UserAgent, AurHosts, AurFirst
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

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
