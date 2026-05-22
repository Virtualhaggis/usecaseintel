# [CRIT] Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare

**Source:** The Hacker News, Aikido, StepSecurity
**Published:** 2026-05-19
**Article:** https://thehackernews.com/2026/05/drupal-to-release-urgent-core-security.html

## Threat Profile

Back to Blog Threat Intel Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosystem A new wave of the Mini Shai-Hulud worm has compromised packages across Alibaba's AntV data visualization ecosystem, echarts-for-react, timeago.js, and dozens more. Stolen CI/CD secrets are being dumped to thousands of public GitHub repositories as the attack continues to spread. Sai Likhith View LinkedIn May 19, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `check.git-service.com`
- **SHA256:** `7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1528** — Steal Application Access Token
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] durabletask C2 contact — check.git-service.com / t.m-kosche.com from python3

`UC_86_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.src_ip) as src_ip values(DNS.query) as query from datamodel=Network_Resolution.DNS where (DNS.query="check.git-service.com" OR DNS.query="*.git-service.com" OR DNS.query="t.m-kosche.com" OR DNS.query="*.m-kosche.com") by DNS.src DNS.src_ip DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*git-service.com*" OR Web.url="*m-kosche.com*" OR Web.dest_ip="160.119.64.3" OR Web.dest_ip="83.142.209.194" OR Web.dest_ip="185.95.159.32") by Web.src Web.src_ip Web.url Web.dest_ip | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
// TeamPCP Mini Shai-Hulud — durabletask supply chain C2
let badDomains = dynamic(["check.git-service.com","git-service.com","t.m-kosche.com","m-kosche.com"]);
let badIPs = dynamic(["160.119.64.3","83.142.209.194","185.95.159.32"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (badDomains) or RemoteIP in (badIPs)
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessParentFileName,
          InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

### [LLM] python3 dropping and detached-spawning /tmp/managed.pyz (durabletask rope.pyz dropper)

`UC_86_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.process_hash) as hashes values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name=python3* AND (Processes.process="*/tmp/managed.pyz*" OR Processes.process_name="managed.pyz" OR Processes.process_hash IN ("069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce","7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8","aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5","877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec","3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf","85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f","c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc")) by host Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// durabletask dropper — python3 spawning /tmp/managed.pyz with detached session
let badHashes = dynamic([
  "069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce",
  "7d80b3ef74ad7992b93c31966962612e4e2ceb93e7727cdbd1d2a9af47d44ba8",
  "aeaf583e20347bf850e2fabdcd6f4982996ba023f8c2cd56bbd299cfd56516f5",
  "877ff2531a63393c4cb9c3c86908b62d9c4fc3db971bc231c48537faae6cb3ec",
  "3de04fe2a76262743ed089efa7115f4508619838e77d60b9a1aab8b20d2cc8bf",
  "85f54c089d78ebfb101454ec934c767065a342a43c9ee1beac8430cdd3b2086f",
  "c0b094e46842260936d4b97ce63e4539b99a3eae48b736798c700217c52569dc"
]);
let procs = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has "/tmp/managed.pyz"
       or FolderPath has "/tmp/managed.pyz"
       or SHA256 in (badHashes)
       or (InitiatingProcessFileName has "python" and FileName =~ "managed.pyz")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath,
              ProcessCommandLine, SHA256, ProcessId,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName, ReportId;
let files = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath == "/tmp/managed.pyz" or FileName =~ "managed.pyz" or SHA256 in (badHashes)
    | where InitiatingProcessFileName has_any ("python","python3","python3.14")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, ReportId;
union procs, files
| order by Timestamp desc
```

### [LLM] GitHub token exfiltration — `gh auth token` / `gh auth status --show-token` spawned by python3

`UC_86_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="gh" AND Processes.parent_process_name IN ("python3","python3.14","python") AND (Processes.process="*auth token*" OR Processes.process="*auth status*--show-token*") by host Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// rope.pyz credential exfil — gh CLI spawned by python3 to dump GitHub tokens
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "gh"
| where ProcessCommandLine has_any ("auth token", "auth status --show-token", "auth status -t")
| where InitiatingProcessFileName has "python"
   or InitiatingProcessParentFileName has "python"
   or InitiatingProcessCommandLine has "/tmp/managed.pyz"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, InitiatingProcessParentId,
          ProcessId, ReportId
| order by Timestamp desc
```

### [LLM] Fake pgsql-monitor systemd persistence dropped by python3

`UC_86_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All.process) as cmd values(All.user) as user from datamodel=Endpoint where (Endpoint.Processes.process="*systemctl*--user*daemon-reload*" AND Endpoint.Processes.parent_process_name IN ("python3","python3.14","python")) OR (Endpoint.Filesystem.file_path="*/.config/systemd/user/pgsql-monitor.service*" OR Endpoint.Filesystem.file_name="pgsql-monitor.service") by host Endpoint.Processes.parent_process | `drop_dm_object_name(All)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// rope.pyz persistence — pgsql-monitor.service systemd unit + python-triggered daemon-reload
let svcWrite = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "pgsql-monitor.service"
       or FolderPath has "/.config/systemd/user/pgsql-monitor"
    | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId;
let daemonReload = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "systemctl"
    | where ProcessCommandLine has "--user" and ProcessCommandLine has "daemon-reload"
    | where InitiatingProcessFileName has "python"
       or InitiatingProcessCommandLine has "/tmp/managed.pyz"
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId;
union svcWrite, daemonReload
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare

`UC_86_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("timeago.js","canvas-nest.js","filesize.js","onfire.js","relationship.js","ribbon.js","slice.js","bun.exe","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/rancher/k3s/k3s.yaml*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("timeago.js","canvas-nest.js","filesize.js","onfire.js","relationship.js","ribbon.js","slice.js","bun.exe","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Drupal to Release Urgent Core Security Updates on May 20, Sites Told to Prepare
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("timeago.js", "canvas-nest.js", "filesize.js", "onfire.js", "relationship.js", "ribbon.js", "slice.js", "bun.exe", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/rancher/k3s/k3s.yaml", "/dev/null") or FileName in~ ("timeago.js", "canvas-nest.js", "filesize.js", "onfire.js", "relationship.js", "ribbon.js", "slice.js", "bun.exe", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `t.m-kosche.com`, `check.git-service.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7c24b4d9a8f448832f3752d7f67dcdbf1b7f0f41e10bf633efa175e627144e8b`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
