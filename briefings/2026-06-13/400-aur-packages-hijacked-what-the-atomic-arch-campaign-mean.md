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
- **T1059.004** — Unix Shell
- **T1059.007** — JavaScript
- **T1552.001** — Credentials in Files
- **T1552.004** — Private Keys
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1567.002** — Exfiltration to Cloud Storage
- **T1199** — Trusted Relationship
- **T1554** — Compromise Host Software Binary
- **T1014** — Rootkit
- **T1547** — Boot or Logon Autostart Execution
- **T1068** — Exploitation for Privilege Escalation
- **T1078.004** — Cloud Accounts
- **T1550.001** — Application Access Token
- **T1657** — Financial Theft (downstream)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AUR helper (yay/paru/makepkg) spawns npm install of atomic-lockfile or js-digest

`UC_11_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("makepkg","pacman","yay","paru","trizen","pikaur","aurman") OR Processes.parent_process_exec IN ("makepkg","pacman","yay","paru")) AND Processes.process_name IN ("npm","node","npx") AND (Processes.process="*atomic-lockfile*" OR Processes.process="*js-digest*" OR Processes.process="*install*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | where like(process, "%atomic-lockfile%") OR like(process, "%js-digest%") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("makepkg","pacman","yay","paru","trizen","pikaur","aurman","bash","sh")
| where FileName in~ ("npm","node","npx")
| where ProcessCommandLine has_any ("atomic-lockfile","js-digest")
   or (ProcessCommandLine has "install" and InitiatingProcessCommandLine has_any ("PKGBUILD",".install","makepkg"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          ChildPath = FolderPath,
          SHA256
| order by Timestamp desc
```

### Non-browser process reads developer credential stores after AUR build window

`UC_11_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_path) as files_touched dc(Filesystem.file_path) as distinct_files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=read AND (Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.config/google-chrome/*/Cookies" OR Filesystem.file_path="*/.mozilla/firefox/*/cookies.sqlite" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*") by Filesystem.dest Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | where distinct_files >= 3 AND NOT match(process_name, "^(firefox|chrome|chromium|brave|opera|gnome-keyring-daemon|seahorse|ssh|git|gh|npm|docker|slack|discord)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredFiles = dynamic([
    "/.ssh/id_rsa","/.ssh/id_ed25519","/.ssh/id_ecdsa","/.ssh/known_hosts",
    "/.npmrc","/.config/gh/hosts.yml","/.docker/config.json",
    "/.aws/credentials","/.aws/config",
    "/.config/google-chrome/Default/Cookies","/.mozilla/firefox/","cookies.sqlite",
    "/.config/Slack/storage/","/.config/discord/","/.config/Microsoft/Microsoft Teams/"]);
let BenignReaders = dynamic(["firefox","chrome","chromium","brave","opera","slack","discord","teams","ssh","sshd","git","gh","npm","docker","podman","aws","gnome-keyring-daemon","seahorse","keepassxc"]);
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileAccessed","FileOpened","FileRead")
| where FolderPath has_any (CredFiles) or FileName has_any (CredFiles)
| where InitiatingProcessFileName !in~ (BenignReaders)
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstAccess = min(Timestamp), LastAccess = max(Timestamp), DistinctFiles = dcount(FolderPath), SampleFiles = make_set(FolderPath, 20)
  by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| where DistinctFiles >= 3
| extend WindowSec = datetime_diff('second', LastAccess, FirstAccess)
| where WindowSec <= 300
| order by FirstAccess desc
```

### Outbound HTTPS from build-host process to temp.sh or fardewoak/nodejs-argo (Atomic Arch C2)

`UC_11_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.dest) as dests from datamodel=Web.Web where (Web.url="*temp.sh*" OR Web.url="*fardewoak/nodejs-argo*" OR Web.dest="temp.sh") AND Web.src_user_name!="*$" by Web.src host_process=Web.user_agent Web.app | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let C2Hosts = dynamic(["temp.sh","github.com/fardewoak/nodejs-argo","raw.githubusercontent.com/fardewoak/nodejs-argo"]);
let BuildProcs = dynamic(["makepkg","pacman","yay","paru","npm","node","npx","curl","wget","bash","sh"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (C2Hosts) or RemoteUrl has "temp.sh" or RemoteUrl has "fardewoak"
| where InitiatingProcessFileName in~ (BuildProcs)
   or InitiatingProcessParentFileName in~ (BuildProcs)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### AUR install of package whose maintainer recently changed (Atomic Arch ownership-takeover)

`UC_11_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.process_name IN ("yay","paru","makepkg","pacman","trizen","pikaur","aurman")) AND (Processes.process="*-S *" OR Processes.process="*--sync*" OR Processes.process="*-Syu*" OR Processes.process="*install*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | join type=inner dest [ | tstats summariesonly=true count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.cache/yay/*/PKGBUILD" OR Filesystem.file_path="*/.cache/paru/*/PKGBUILD" OR Filesystem.file_path="*/.install") AND Filesystem.action=create by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let KnownAttackerMaintainers = dynamic(["krisztinavarga","custodiatovar","veramagalhaes","herbsobering"]);
let HelperProcs = dynamic(["yay","paru","makepkg","pacman","trizen","pikaur","aurman"]);
let HelperInvocations =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ (HelperProcs) or FileName in~ (HelperProcs)
    | where ProcessCommandLine has_any ("-S ","--sync","-Syu","install","-Ss")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine;
let PkgbuildWrites =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified")
    | where FolderPath has_any ("/.cache/yay/","/.cache/paru/","/aur/","/AUR/")
           or FileName == "PKGBUILD" or FileName endswith ".install"
    | project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName;
HelperInvocations
| join kind=inner (PkgbuildWrites) on DeviceName
| where Timestamp1 between (Timestamp - 5m .. Timestamp + 15m)
| extend Maintainer = extract(@"# Maintainer:\s*([\w._-]+)", 1, FolderPath)
| extend FlaggedMaintainer = iff(Maintainer in~ (KnownAttackerMaintainers), true, false)
| project Timestamp, DeviceName, AccountName, HelperCmd = ProcessCommandLine, PkgbuildPath = strcat(FolderPath, FileName), FlaggedMaintainer
| order by Timestamp desc
```

### eBPF program load on developer / CI build host (Atomic Arch rootkit persistence)

`UC_11_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*bpf(*" OR Processes.process="*BPF_PROG_LOAD*" OR Processes.process="*bpftool prog load*") AND Processes.user="root" by Processes.dest Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT match(parent_process_name, "^(systemd|bpftrace|tetragon|tracee-ebpf|cilium-agent|kubelet|falco|kube-proxy|datadog-agent)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BenignBpfLoaders = dynamic(["bpftrace","tetragon","tracee-ebpf","cilium-agent","kubelet","falco","kube-proxy","datadog-agent","systemd","snapd","firewalld","iptables","nft"]);
let RecentAurActivity =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("makepkg","pacman","yay","paru")
    | distinct DeviceId;
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath startswith "/sys/fs/bpf/" and ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName !in~ (BenignBpfLoaders)
| where InitiatingProcessAccountName == "root"
| join kind=inner RecentAurActivity on DeviceId
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          BpfObject = strcat(FolderPath, FileName), SHA256 = InitiatingProcessSHA256
| order by Timestamp desc
```

### Developer cloud/SaaS token use from new ASN post-Atomic-Arch host compromise

`UC_11_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src_ips values(Authentication.src_user_agent) as user_agents from datamodel=Authentication where Authentication.action=success AND Authentication.app IN ("github","npm","aws","gcp","azure","vault","docker") by Authentication.user Authentication.app Authentication.src_user_bunit | `drop_dm_object_name(Authentication)` | lookup user_baseline_asn user as user OUTPUT baseline_asns | where NOT mvfind(src_ips, baseline_asns) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RecentAurHosts =
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("makepkg","pacman","yay","paru") and ProcessCommandLine has_any ("-S ","--sync","-Syu","install")
    | summarize by DeviceId, AccountUpn = tostring(InitiatingProcessAccountUpn)
    | where isnotempty(AccountUpn);
let UserBaseline =
    AADSignInEventsBeta
    | where Timestamp between (ago(60d) .. ago(7d))
    | where ErrorCode == 0
    | summarize BaselineIPs = make_set(IPAddress, 200), BaselineCountries = make_set(Country, 20) by AccountUpn;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where Application has_any ("GitHub","npm","Docker","AWS","Azure CLI","Vault","Google Cloud")
| join kind=inner RecentAurHosts on $left.AccountUpn == $right.AccountUpn
| join kind=leftouter UserBaseline on AccountUpn
| where IPAddress !in (BaselineIPs) and Country !in (BaselineCountries)
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, UserAgent, ClientAppUsed, RiskLevelDuringSignIn
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
