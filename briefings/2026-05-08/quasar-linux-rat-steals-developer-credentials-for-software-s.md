# [CRIT] Quasar Linux RAT Steals Developer Credentials for Software Supply Chain Compromise

**Source:** The Hacker News
**Published:** 2026-05-08
**Article:** https://thehackernews.com/2026/05/quasar-linux-rat-steals-developer.html

## Threat Profile

Quasar Linux RAT Steals Developer Credentials for Software Supply Chain Compromise 
 Ravie Lakshmanan  May 08, 2026 Linux / DevOps 
A previously undocumented Linux implant codenamed Quasar Linux RAT (QLNX) is targeting developers' systems to establish a silent foothold as well as facilitate a broad range of post-compromise functionality, such as credential harvesting, keylogging, file manipulation, clipboard monitoring, and network tunneling.
"QLNX targets developers and DevOps credentials acr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1556.003** — Modify Authentication Process: Pluggable Authentication Modules
- **T1014** — Rootkit
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] QLNX developer-credential fan-out: single process reading multiple secret files (.npmrc/.pypirc/.aws/.kube/.docker/.vault-token/.env)

`UC_6_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as touched_files dc(Filesystem.file_path) as unique_secret_files from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.pypirc*" OR Filesystem.file_path="*/.git-credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.vault-token*" OR Filesystem.file_path="*/.terraformrc*" OR Filesystem.file_path="*/terraform.rc*" OR Filesystem.file_path="*/.config/gh/hosts.yml*" OR Filesystem.file_path="*/.env") by Filesystem.dest Filesystem.process_id Filesystem.process_name _time span=5m | where unique_secret_files>=3 | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(git|gh|aws|kubectl|helm|docker|terraform|npm|yarn|pip|pip3|poetry|vault|cat|less|grep|find|node|python|python3)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// QLNX credential harvester — one Linux process reading 3+ distinct developer secret files
let _qlnx_secret_files = dynamic([".npmrc",".pypirc",".git-credentials",".vault-token","credentials","config.json","config",".terraformrc","terraform.rc","hosts.yml",".env"]);
let _qlnx_secret_paths = dynamic(["/.aws/credentials","/.kube/config","/.docker/config.json","/.config/gh/hosts.yml","/.terraform.d/credentials.tfrc.json"]);
let _allowed_readers = dynamic(["git","gh","aws","kubectl","helm","docker","dockerd","terraform","npm","node","yarn","pip","pip3","poetry","vault","ansible","ansible-playbook","python","python3","cat","less","more","grep","find","sshd"]);
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FileName in (_qlnx_secret_files) and (FolderPath has "/.aws/" or FolderPath has "/.kube/" or FolderPath has "/.docker/" or FolderPath has "/.config/gh/" or FolderPath has "/.terraform.d/" or FolderPath matches regex @"/home/[^/]+" or FolderPath matches regex @"/root"))
   or _qlnx_secret_paths has_any (FolderPath)
| where InitiatingProcessFileName !in~ (_allowed_readers)
| summarize SecretFiles = make_set(strcat(FolderPath, "/", FileName), 25), UniqueSecrets = dcount(strcat(FolderPath, "/", FileName)), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleCmd = any(InitiatingProcessCommandLine) by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp, 5m)
| where UniqueSecrets >= 3
| order by LastSeen desc
```

### [LLM] QLNX userland rootkit / PAM backdoor: write to /etc/ld.so.preload or PAM module directories

`UC_6_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/ld.so.preload" OR Filesystem.file_path="/etc/ld.so.preload.d/*" OR Filesystem.file_path="/lib/security/pam_*.so" OR Filesystem.file_path="/lib64/security/pam_*.so" OR Filesystem.file_path="/lib/x86_64-linux-gnu/security/pam_*.so" OR Filesystem.file_path="/usr/lib/security/pam_*.so" OR Filesystem.file_path="/usr/lib64/security/pam_*.so" OR Filesystem.file_path="/usr/lib/x86_64-linux-gnu/security/pam_*.so") (Filesystem.action=created OR Filesystem.action=modified OR Filesystem.action=written) by Filesystem.dest Filesystem.process_id Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(dpkg|apt|apt-get|aptitude|unattended-upgr|rpm|dnf|yum|zypper|pacman|snap|snapd|update-manager|cfengine-execd|puppet|chef-client|salt-minion|ansible-playbook|systemd|systemd-tmpfiles|authconfig|pam-auth-update)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// QLNX userland rootkit (LD_PRELOAD) + PAM inline-hook backdoor file writes
let _pkg_managers = dynamic(["dpkg","apt","apt-get","aptitude","unattended-upgr","rpm","dnf","yum","zypper","pacman","snap","snapd","systemd","systemd-tmpfiles","authconfig","pam-auth-update","update-manager","puppet","chef-client","salt-minion","ansible-playbook","cfengine-execd"]);
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath == "/etc" and FileName == "ld.so.preload")
     or (FolderPath startswith "/etc/ld.so.preload.d")
     or (FolderPath endswith "/security" and FileName startswith "pam_" and FileName endswith ".so" and (FolderPath startswith "/lib/" or FolderPath startswith "/lib64/" or FolderPath startswith "/usr/lib/" or FolderPath startswith "/usr/lib64/"))
| where InitiatingProcessFileName !in~ (_pkg_managers)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, ParentImage = InitiatingProcessParentFileName, Image = InitiatingProcessFileName, Cmd = InitiatingProcessCommandLine, ImageSHA256 = InitiatingProcessSHA256, DroppedPath = strcat(FolderPath, "/", FileName), DroppedSHA256 = SHA256, ActionType
| order by Timestamp desc
```

### [LLM] QLNX shell-injection persistence: append to .bashrc / .bash_profile / .profile / /etc/profile.d by non-shell process

`UC_6_7` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_path) as process_path values(Filesystem.user) as actor from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".bashrc" OR Filesystem.file_name=".bash_profile" OR Filesystem.file_name=".bash_login" OR Filesystem.file_name=".profile" OR Filesystem.file_name=".zshrc" OR Filesystem.file_name=".zprofile" OR Filesystem.file_path="/etc/profile" OR Filesystem.file_path="/etc/bash.bashrc" OR Filesystem.file_path="/etc/profile.d/*") (Filesystem.action=modified OR Filesystem.action=created OR Filesystem.action=written) by Filesystem.dest Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where NOT match(process_name,"(?i)^(vim|vi|nano|emacs|gedit|kate|code|nvim|sed|bash|zsh|sh|dash|chsh|adduser|useradd|usermod|cloud-init|ansible-playbook|puppet|chef-client|salt-minion|dpkg|apt|apt-get|rpm|dnf|yum)$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// QLNX shell-rc persistence — non-editor / non-shell process modifying bash/zsh rc files
let _allowed_writers = dynamic(["vim","vi","nano","emacs","gedit","kate","code","nvim","sed","awk","bash","zsh","sh","dash","chsh","adduser","useradd","usermod","cloud-init","ansible-playbook","puppet","chef-client","salt-minion","dpkg","apt","apt-get","rpm","dnf","yum","snap","snapd","systemd","systemd-tmpfiles"]);
let _rc_files = dynamic([".bashrc",".bash_profile",".bash_login",".profile",".zshrc",".zprofile",".zlogin","bash.bashrc","profile"]);
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in (_rc_files) or FolderPath startswith "/etc/profile.d"
| where (FolderPath matches regex @"^/(home/[^/]+|root)$") or (FolderPath == "/etc" and FileName in ("profile","bash.bashrc")) or (FolderPath startswith "/etc/profile.d")
| where InitiatingProcessFileName !in~ (_allowed_writers)
| where InitiatingProcessFolderPath !startswith "/usr/lib/snapd/"
| project Timestamp, DeviceName, InitiatingProcessAccountName, Image = InitiatingProcessFileName, ImagePath = InitiatingProcessFolderPath, Cmd = InitiatingProcessCommandLine, ImageSHA256 = InitiatingProcessSHA256, ModifiedFile = strcat(FolderPath, "/", FileName), ActionType
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
