# [CRIT] Active Supply Chain Attack: Malicious node-ipc Versions Published to npm

**Source:** StepSecurity
**Published:** 2026-05-19
**Article:** https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack

## Threat Profile

Back to Blog Threat Intel Active Supply Chain Attack: Malicious node-ipc Versions Published to npm Active Supply Chain Attack: Malicious node-ipc Versions Published to npm StepSecurity has detected multiple malicious releases of the popular node-ipc npm package. Three versions are currently known to be compromised, containing an obfuscated payload designed to steal cloud credentials, SSH keys, and CI/CD secrets. Our team is actively analyzing the attack, and this post will be updated as our inve…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sh.azurestaticprovider.net`
- **SHA256:** `bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1568** — Dynamic Resolution
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### node-ipc C2 callback to sh.azurestaticprovider.net (May 2026 npm supply-chain)

`UC_275_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest values(DNS.answer) as resolved_ip from datamodel=Network_Resolution where DNS.query="*azurestaticprovider.net" OR DNS.query="sh.azurestaticprovider.net" by DNS.query host | `drop_dm_object_name(DNS)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.app) as app from datamodel=Network_Traffic where All_Traffic.dest="*azurestaticprovider.net" OR All_Traffic.url="*azurestaticprovider.net*" by All_Traffic.dest host | `drop_dm_object_name(All_Traffic)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// node-ipc supply-chain C2: any host contacting sh.azurestaticprovider.net
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "azurestaticprovider.net" or RemoteUrl =~ "sh.azurestaticprovider.net"
| where InitiatingProcessAccountName !endswith "$"     // exclude machine-account noise
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Compromised node-ipc.cjs bundle write (~117KB) under node_modules

`UC_275_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as writer_process values(Filesystem.file_hash) as sha256 from datamodel=Endpoint.Filesystem where Filesystem.file_path="*node_modules*node-ipc*node-ipc.cjs" AND Filesystem.file_size>80000 AND _time>=strptime("2026-05-14","%Y-%m-%d") by Filesystem.dest Filesystem.file_path Filesystem.file_size | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// Malicious node-ipc bundle write — anomalous .cjs size under node_modules
DeviceFileEvents
| where Timestamp > datetime(2026-05-14T00:00:00Z)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has @"\node_modules\node-ipc\" or FolderPath has "/node_modules/node-ipc/"
| where FileName =~ "node-ipc.cjs"
| where FileSize > 80000     // clean ~37KB; trojanised ~117KB (80KB IIFE injected)
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Node.js process bulk-reading cloud & SCM credential files in single session

`UC_275_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_path) as distinct_cred_files values(Filesystem.file_path) as files_sample min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node") AND (Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.aws/config*" OR Filesystem.file_path="*/.ssh/id_rsa*" OR Filesystem.file_path="*/.ssh/id_ed25519*" OR Filesystem.file_path="*/.ssh/id_ecdsa*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/.azure/accessTokens*" OR Filesystem.file_path="*/.azure/azureProfile*" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*/.terraform.d/*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.netrc*" OR Filesystem.file_path="*/.gitconfig*" OR Filesystem.file_path="*/.config/gh/*" OR Filesystem.file_path="*/.claude/*" OR Filesystem.file_path="*/.kiro/*" OR Filesystem.file_path="*/.bash_history*" OR Filesystem.file_path="*/.zsh_history*") by Filesystem.dest Filesystem.process_guid Filesystem.user | `drop_dm_object_name(Filesystem)` | where distinct_cred_files >= 3 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// node process touching multiple credential-store paths in one session — post-require('node-ipc') harvest pattern
let CredPathSubstrings = dynamic([
    @"\.aws\credentials", @"\.aws\config",
    @"\.ssh\id_rsa", @"\.ssh\id_ed25519", @"\.ssh\id_ecdsa", @"\.ssh\known_hosts",
    @"\.kube\config",
    @"\.azure\accessTokens", @"\.azure\azureProfile",
    @"\.config\gcloud\", @"\.config\gh\",
    @"\.terraform.d\", @"\.docker\config.json",
    @"\.npmrc", @"\.netrc", @"\.gitconfig",
    @"\.claude\", @"\.kiro\",
    @"\.bash_history", @"\.zsh_history", @"\.psql_history",
    "/.aws/", "/.ssh/", "/.kube/", "/.azure/",
    "/.config/gcloud/", "/.config/gh/", "/.terraform.d/",
    "/.docker/config.json", "/.npmrc", "/.netrc", "/.gitconfig",
    "/.claude/", "/.kiro/", "/.bash_history", "/.zsh_history"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessAccountName !endswith "$"
| extend FullPath = strcat(FolderPath, FileName)
| where FullPath has_any (CredPathSubstrings)
| summarize DistinctCredPaths = dcount(FullPath),
            CredFilesSample = make_set(FullPath, 30),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleCmdLine = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessAccountName
| where DistinctCredPaths >= 3
| order by LastSeen desc
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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

### Article-specific behavioural hunt — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm

`UC_275_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","node-ipc.js","bt.node.js",".bt.node.js","router_init.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/ssh/ssh_host_*" OR Filesystem.file_path="*/var/run/secrets/kubernetes.io/serviceaccount/token*" OR Filesystem.file_path="*/etc/rancher/k3s/k3s.yaml*" OR Filesystem.file_path="*/Library/Keychains/*" OR Filesystem.file_path="*/tmp/nt-1234/abc.tar.gz*" OR Filesystem.file_path="*/tmp/nt-*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js","node-ipc.js","bt.node.js",".bt.node.js","router_init.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Active Supply Chain Attack: Malicious node-ipc Versions Published to npm
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "node-ipc.js", "bt.node.js", ".bt.node.js", "router_init.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/ssh/ssh_host_", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/etc/rancher/k3s/k3s.yaml", "/Library/Keychains/", "/tmp/nt-1234/abc.tar.gz", "/tmp/nt-", "/dev/null") or FileName in~ ("node.js", "node-ipc.js", "bt.node.js", ".bt.node.js", "router_init.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sh.azurestaticprovider.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `bf9d8c0c3ed3ceaa831a13de27f1b1c7c7b7f01d2db4103bfdba4191940b0301`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
