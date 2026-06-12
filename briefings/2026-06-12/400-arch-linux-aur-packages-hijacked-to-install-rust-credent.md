# [HIGH] 400+ Arch Linux AUR Packages Hijacked to Install Rust Credential Stealer

**Source:** The Hacker News
**Published:** 2026-06-12
**Article:** https://thehackernews.com/2026/06/400-arch-linux-aur-packages-hijacked-to.html

## Threat Profile

400+ Arch Linux AUR Packages Hijacked to Install Rust Credential Stealer 
 Ravie Lakshmanan  Jun 12, 2026 Linux / Supply Chain Attack 
Attackers took over more than 400 packages in the Arch User Repository (AUR) this week and rewrote their build scripts to install a credential stealer on any machine that built them.
The malware is a Rust binary built to harvest developer secrets. When it lands with root, it can also load an eBPF rootkit to hide itself. The AUR is Arch Linux's community package…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `temp.sh`
- **Domain (defanged):** `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion`
- **SHA256:** `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b`
- **MD5:** `42b59fdbe1b72895b2951412222ebf40`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1014** — Rootkit
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567.002** — Exfiltration to Cloud Storage
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Atomic Arch AUR build invokes 'npm install atomic-lockfile' or 'bun install js-digest'

`UC_0_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="npm" OR Processes.process_name="bun") (Processes.process="*install atomic-lockfile*" OR Processes.process="*install js-digest*") (Processes.parent_process_name="makepkg" OR Processes.parent_process_name="fakeroot" OR Processes.parent_process_name="bash" OR Processes.parent_process_name="sh") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name("Processes")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("npm", "bun")
| where ProcessCommandLine has_any ("atomic-lockfile", "js-digest")
| where InitiatingProcessFileName in~ ("makepkg", "fakeroot", "bash", "sh", "zsh", "dash")
   or InitiatingProcessCommandLine has_any ("PKGBUILD", ".install", "makepkg")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentName = InitiatingProcessFileName,
          ParentCmd  = InitiatingProcessCommandLine,
          ParentFolder = InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Atomic Arch 'deps' ELF execution by hash or src/hooks/deps path

`UC_0_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b" OR Processes.process_hash="42b59fdbe1b72895b2951412222ebf40" OR Processes.process_path="*/src/hooks/deps" OR Processes.process_name="deps") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process_hash Processes.parent_process_name Processes.parent_process | `drop_dm_object_name("Processes")`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 == "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
   or MD5 == "42b59fdbe1b72895b2951412222ebf40"
   or FolderPath has "/src/hooks/deps"
   or (FileName =~ "deps" and InitiatingProcessFileName in~ ("npm", "node", "bun"))
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, SHA256, MD5,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Cmd = ProcessCommandLine
| order by Timestamp desc
```

### Atomic Arch systemd persistence — Restart=always unit dropped outside package manager

`UC_0_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/*.service" OR Filesystem.file_path="*/.config/systemd/user/*.service") (Filesystem.process_name!="pacman" Filesystem.process_name!="makepkg" Filesystem.process_name!="systemctl" Filesystem.process_name!="systemd" Filesystem.process_name!="apt" Filesystem.process_name!="dpkg" Filesystem.process_name!="yay" Filesystem.process_name!="paru") Filesystem.action="created" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name("Filesystem")`
```

**Defender KQL:**
```kql
let suspicious_units = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath matches regex @"^/etc/systemd/system/[^/]+\.service$"
         or FolderPath matches regex @"\.config/systemd/user/[^/]+\.service$"
    | where InitiatingProcessFileName !in~ ("pacman", "makepkg", "systemctl", "systemd", "apt", "apt-get", "dpkg", "yay", "paru", "snapd", "dnf", "rpm");
let payload_drops = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath startswith "/var/lib/" or FolderPath has "/.config/"
    | where FileSize between (50000 .. 50000000)
    | project DropTime = Timestamp, DeviceId, DropPath = FolderPath, DropProc = InitiatingProcessFileName, DropSHA = SHA256;
suspicious_units
| join kind=inner payload_drops on DeviceId
| where DropTime between (Timestamp - 5m .. Timestamp + 5m)
| project Timestamp, DeviceName, InitiatingProcessAccountName, UnitPath = FolderPath,
          UnitWrittenBy = InitiatingProcessFileName,
          UnitWriterCmd = InitiatingProcessCommandLine,
          DropPath, DropProc, DropSHA
```

### Atomic Arch eBPF rootkit — pinned BPF map named hidden_pids / hidden_names / hidden_inodes

`UC_0_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/sys/fs/bpf/hidden_pids*" OR Filesystem.file_path="/sys/fs/bpf/hidden_names*" OR Filesystem.file_path="/sys/fs/bpf/hidden_inodes*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path Filesystem.action | `drop_dm_object_name("Filesystem")`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has "/sys/fs/bpf/"
| where FileName in~ ("hidden_pids", "hidden_names", "hidden_inodes")
   or FolderPath has_any ("/sys/fs/bpf/hidden_pids", "/sys/fs/bpf/hidden_names", "/sys/fs/bpf/hidden_inodes")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
          FolderPath, FileName,
          WrittenBy = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          WriterFolder = InitiatingProcessFolderPath,
          SHA256
| order by Timestamp desc
```

### Atomic Arch credential file fan-out — non-browser process reads browser / SSH / Vault secrets after AUR build

`UC_0_15` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Filesystem.file_path) as touched_files dc(Filesystem.file_name) as distinct_files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action="read" (Filesystem.file_path="*/.config/google-chrome/*Cookies*" OR Filesystem.file_path="*/.config/chromium/*Cookies*" OR Filesystem.file_path="*/.config/BraveSoftware/*Cookies*" OR Filesystem.file_path="*/.config/microsoft-edge/*Cookies*" OR Filesystem.file_path="*/.mozilla/firefox/*/cookies.sqlite" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.ssh/known_hosts" OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.vault-token" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.config/Slack/*" OR Filesystem.file_path="*/.config/discord/*" OR Filesystem.file_path="*/.config/Microsoft/Microsoft Teams/*") (Filesystem.process_name!="chrome" Filesystem.process_name!="firefox" Filesystem.process_name!="brave" Filesystem.process_name!="msedge" Filesystem.process_name!="slack" Filesystem.process_name!="discord" Filesystem.process_name!="teams" Filesystem.process_name!="ssh" Filesystem.process_name!="git" Filesystem.process_name!="npm" Filesystem.process_name!="docker" Filesystem.process_name!="vault") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path | `drop_dm_object_name("Filesystem")` | where distinct_files >= 3
```

**Defender KQL:**
```kql
let CredTargets = dynamic([
  "/.config/google-chrome/", "/.config/chromium/", "/.config/BraveSoftware/",
  "/.config/microsoft-edge/", "/.mozilla/firefox/", "/.ssh/id_",
  "/.ssh/known_hosts", "/.npmrc", "/.vault-token", "/.docker/config.json",
  "/.config/Slack/", "/.config/discord/", "/.config/Microsoft/Microsoft Teams/",
  "/.bash_history", "/.zsh_history", "/.config/podman/"
]);
let AllowedReaders = dynamic([
  "chrome", "chromium", "firefox", "firefox-bin", "brave", "msedge",
  "slack", "discord", "teams", "ssh", "sshd", "git", "git-credential",
  "npm", "node", "docker", "dockerd", "podman", "vault", "gpg", "gnome-keyring",
  "bash", "zsh", "fish"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileOpened", "FileAccessed")
| where FolderPath has_any (CredTargets)
| where InitiatingProcessFileName !in~ (AllowedReaders)
| summarize DistinctTargets = dcount(FolderPath),
            TouchedSample = make_set(FolderPath, 25),
            FirstAccess = min(Timestamp), LastAccess = max(Timestamp)
            by DeviceId, DeviceName, InitiatingProcessAccountName,
               InitiatingProcessFileName, InitiatingProcessSHA256
| where DistinctTargets >= 3
| order by DistinctTargets desc
```

### Atomic Arch Tor loopback C2 — process connects to 127.0.0.1:9050/9150 right after AUR build

`UC_0_16` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="127.0.0.1" OR All_Traffic.dest_ip="::1") (All_Traffic.dest_port=9050 OR All_Traffic.dest_port=9150 OR All_Traffic.dest_port=9051) (All_Traffic.process_name!="tor" All_Traffic.process_name!="firefox" All_Traffic.process_name!="torbrowser*" All_Traffic.process_name!="tor-browser*" All_Traffic.process_name!="nyx" All_Traffic.process_name!="arm") by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.process_path All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIPType in ("Loopback", "Private")
| where RemoteIP in ("127.0.0.1", "::1")
| where RemotePort in (9050, 9051, 9150)
| where InitiatingProcessFileName !in~ ("tor", "firefox", "firefox-bin", "torbrowser", "tor-browser", "nyx", "arm", "obfs4proxy")
| where InitiatingProcessFolderPath !has "tor-browser"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Initiator = InitiatingProcessFileName,
          InitiatorFolder = InitiatingProcessFolderPath,
          InitiatorCmd = InitiatingProcessCommandLine,
          InitiatorSHA = InitiatingProcessSHA256,
          RemoteIP, RemotePort
| order by Timestamp desc
```

### Atomic Arch exfil — HTTP upload to temp.sh from a developer / build host

`UC_0_17` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(All_Traffic.dest_port) as ports min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*temp.sh*" OR All_Traffic.dest="temp.sh" OR All_Traffic.dest="*.temp.sh") (All_Traffic.process_name!="firefox" All_Traffic.process_name!="chrome" All_Traffic.process_name!="chromium" All_Traffic.process_name!="brave" All_Traffic.process_name!="msedge" All_Traffic.process_name!="safari") by All_Traffic.dest All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.process_path All_Traffic.url | `drop_dm_object_name("All_Traffic")`
```

**Defender KQL:**
```kql
let DnsHits = DeviceEvents
    | where Timestamp > ago(14d)
    | where ActionType == "DnsQueryResponse"
    | where AdditionalFields has "temp.sh"
    | project DnsTime = Timestamp, DeviceId, DnsAdditional = AdditionalFields;
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has "temp.sh" or RemoteUrl endswith "temp.sh"
    | where InitiatingProcessFileName !in~ ("firefox", "firefox-bin", "chrome", "chromium", "brave", "msedge", "safari")
    | project Timestamp, DeviceId, DeviceName, AccountName,
              Initiator = InitiatingProcessFileName,
              InitiatorFolder = InitiatingProcessFolderPath,
              InitiatorCmd = InitiatingProcessCommandLine,
              InitiatorSHA = InitiatingProcessSHA256,
              RemoteUrl, RemoteIP, RemotePort;
NetHits
| union (DnsHits | extend NoteOnly = "DNS only — no HTTP yet")
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — 400+ Arch Linux AUR Packages Hijacked to Install Rust Credential Stealer

`UC_0_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 400+ Arch Linux AUR Packages Hijacked to Install Rust Credential Stealer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("temp.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/lib/*" OR Filesystem.file_path="*/etc/systemd/system/*" OR Filesystem.file_path="*/var/lib/.*" OR Filesystem.file_name IN ("temp.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 400+ Arch Linux AUR Packages Hijacked to Install Rust Credential Stealer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("temp.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/lib/", "/etc/systemd/system/", "/var/lib/.") or FileName in~ ("temp.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `temp.sh`, `olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b`, `42b59fdbe1b72895b2951412222ebf40`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 18 use case(s) fired, 28 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
