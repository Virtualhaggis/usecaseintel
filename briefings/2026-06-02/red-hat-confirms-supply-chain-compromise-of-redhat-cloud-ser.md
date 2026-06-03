# [HIGH] Red Hat Confirms Supply Chain Compromise of @redhat-cloud-services npm Packages

**Source:** Cyber Security News, StepSecurity
**Published:** 2026-06-02
**Article:** https://cybersecuritynews.com/red-hat-supply-chain-compromise/

## Threat Profile

Back to Blog Threat Intel Multiple redhat-cloud-services npm Packages compromised Several packages in the @redhat-cloud-services npm scope were found to carry malicious payloads that fire via a preinstall hook on every npm install. The affected versions span multiple packages across the RedHat Cloud Services frontend ecosystem. The payload is a sophisticated multi-stage credential harvester that targets GitHub Actions secrets, AWS, GCP, Azure, Kubernetes, HashiCorp Vault, npm tokens, and CircleC…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `8bf051251ec3b973e39a313547e53421a2f8d2f6`
- **SHA1:** `608d01124cd6b5b8c55888e984b4c4d9b06fa686`
- **SHA1:** `ab9903d9edc720d1e11ea7d3d3e7a1c456f44ff7`
- **SHA1:** `7569d69cf3684a792ce63d19b6e0d9d192597963`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — JavaScript
- **T1105** — Ingress Tool Transfer
- **T1546.016** — Installer Packages
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1552.001** — Credentials in Files
- **T1552.005** — Cloud Instance Metadata API
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Install of compromised @redhat-cloud-services npm package versions (Miasma)

`UC_11_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm","npm.exe","node","node.exe","yarn","yarn.exe","pnpm","pnpm.exe")) (Processes.process="*@redhat-cloud-services/host-inventory-client@5.0.3*" OR Processes.process="*@redhat-cloud-services/notifications-client@6.1.4*" OR Processes.process="*@redhat-cloud-services/types@3.6.1*" OR Processes.process="*@redhat-cloud-services/frontend-components-utilities@7.4.1*" OR Processes.process="*@redhat-cloud-services/frontend-components@7.7.2*" OR Processes.process="*@redhat-cloud-services/rbac-client@9.0.3*" OR Processes.process="*@redhat-cloud-services/javascript-clients-shared@2.0.8*" OR Processes.process="*@redhat-cloud-services/frontend-components-config-utilities@4.11.2*" OR Processes.process="*@redhat-cloud-services/frontend-components-notifications@6.9.2*" OR Processes.process="*@redhat-cloud-services/tsc-transform-imports@1.2.2*" OR Processes.process="*@redhat-cloud-services/frontend-components-config@6.11.3*" OR Processes.process="*@redhat-cloud-services/chrome@2.3.1*" OR Processes.process="*@redhat-cloud-services/eslint-config-redhat-cloud-services@3.2.1*" OR Processes.process="*@redhat-cloud-services/rule-components@4.7.2*" OR Processes.process="*@redhat-cloud-services/frontend-components-remediations@4.9.2*" OR Processes.process="*@redhat-cloud-services/frontend-components-translations@4.4.1*" OR Processes.process="*@redhat-cloud-services/frontend-components-advisor-components@3.8.2*" OR Processes.process="*@redhat-cloud-services/entitlements-client@4.0.11*" OR Processes.process="*@redhat-cloud-services/compliance-client@4.0.3*" OR Processes.process="*@redhat-cloud-services/sources-client@3.0.10*" OR Processes.process="*@redhat-cloud-services/integrations-client@6.0.4*" OR Processes.process="*@redhat-cloud-services/frontend-components-testing@1.2.1*" OR Processes.process="*@redhat-cloud-services/remediations-client@4.0.4*" OR Processes.process="*@redhat-cloud-services/insights-client@4.0.4*" OR Processes.process="*@redhat-cloud-services/topological-inventory-client@3.0.10*" OR Processes.process="*@redhat-cloud-services/config-manager-client@5.0.4*" OR Processes.process="*@redhat-cloud-services/hcc-pf-mcp@0.6.1*" OR Processes.process="*@redhat-cloud-services/quickstarts-client@4.0.11*" OR Processes.process="*@redhat-cloud-services/patch-client@4.0.4*" OR Processes.process="*@redhat-cloud-services/hcc-feo-mcp@0.3.1*" OR Processes.process="*@redhat-cloud-services/hcc-kessel-mcp@0.3.1*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time)
```

**Defender KQL:**
```kql
let MaliciousPkgs = dynamic([
  "@redhat-cloud-services/host-inventory-client@5.0.3",
  "@redhat-cloud-services/notifications-client@6.1.4",
  "@redhat-cloud-services/types@3.6.1",
  "@redhat-cloud-services/frontend-components-utilities@7.4.1",
  "@redhat-cloud-services/frontend-components@7.7.2",
  "@redhat-cloud-services/rbac-client@9.0.3",
  "@redhat-cloud-services/javascript-clients-shared@2.0.8",
  "@redhat-cloud-services/frontend-components-config-utilities@4.11.2",
  "@redhat-cloud-services/frontend-components-notifications@6.9.2",
  "@redhat-cloud-services/tsc-transform-imports@1.2.2",
  "@redhat-cloud-services/frontend-components-config@6.11.3",
  "@redhat-cloud-services/chrome@2.3.1",
  "@redhat-cloud-services/eslint-config-redhat-cloud-services@3.2.1",
  "@redhat-cloud-services/rule-components@4.7.2",
  "@redhat-cloud-services/frontend-components-remediations@4.9.2",
  "@redhat-cloud-services/frontend-components-translations@4.4.1",
  "@redhat-cloud-services/frontend-components-advisor-components@3.8.2",
  "@redhat-cloud-services/entitlements-client@4.0.11",
  "@redhat-cloud-services/compliance-client@4.0.3",
  "@redhat-cloud-services/sources-client@3.0.10",
  "@redhat-cloud-services/integrations-client@6.0.4",
  "@redhat-cloud-services/frontend-components-testing@1.2.1",
  "@redhat-cloud-services/remediations-client@4.0.4",
  "@redhat-cloud-services/insights-client@4.0.4",
  "@redhat-cloud-services/topological-inventory-client@3.0.10",
  "@redhat-cloud-services/config-manager-client@5.0.4",
  "@redhat-cloud-services/hcc-pf-mcp@0.6.1",
  "@redhat-cloud-services/quickstarts-client@4.0.11",
  "@redhat-cloud-services/patch-client@4.0.4",
  "@redhat-cloud-services/hcc-feo-mcp@0.3.1",
  "@redhat-cloud-services/hcc-kessel-mcp@0.3.1"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("npm","npm.exe","node","node.exe","yarn","yarn.exe","pnpm","pnpm.exe","npm-cli.js")
   or InitiatingProcessFileName in~ ("npm","npm.exe","node","node.exe","yarn","yarn.exe","pnpm","pnpm.exe")
| where ProcessCommandLine has_any (MaliciousPkgs)
   or InitiatingProcessCommandLine has_any (MaliciousPkgs)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] node process fetching bun-v1.3.13 from GitHub releases CDN to /tmp

`UC_11_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app=node OR All_Traffic.process_name=node OR All_Traffic.process_name=node.exe) (All_Traffic.url="*oven-sh/bun*" OR All_Traffic.url="*bun-v1.3.13*" OR All_Traffic.dest="objects.githubusercontent.com") by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.url All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | join type=outer src [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_name=bun OR Filesystem.file_path="/tmp/*/bun*") by Filesystem.dest Filesystem.file_path Filesystem.process_name | rename Filesystem.dest as src | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let BunWindow = 15m;
let NetHits = DeviceNetworkEvents
  | where Timestamp > ago(7d)
  | where InitiatingProcessFileName in~ ("node","node.exe")
  | where RemoteUrl has_any ("oven-sh/bun","bun-v1.3.13","bun-linux-x64","bun-darwin","bun-windows-x64")
     or (RemoteUrl has "objects.githubusercontent.com" and InitiatingProcessCommandLine has_any ("index.js","preinstall"))
  | project NetTime=Timestamp, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCommandLine, RemoteUrl, RemoteIP;
let FileHits = DeviceFileEvents
  | where Timestamp > ago(7d)
  | where InitiatingProcessFileName in~ ("node","node.exe")
  | where FolderPath startswith "/tmp/" and (FileName == "bun" or FileName startswith "bun-v1.3.13" or FileName endswith ".zip")
  | project FileTime=Timestamp, DeviceId, DeviceName, InitiatingProcessId, FolderPath, FileName, SHA256;
NetHits
| join kind=inner FileHits on DeviceId, InitiatingProcessId
| where abs(datetime_diff('second', NetTime, FileTime)) <= 900
| project NetTime, FileTime, DeviceName, InitiatingProcessCommandLine, RemoteUrl, FolderPath, FileName, SHA256
| order by NetTime desc
```

### [LLM] Bun runtime executing /tmp/p<random>.js spawned by node preinstall

`UC_11_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=node OR Processes.parent_process_name=node.exe) (Processes.process_path="/tmp/*/bun*" OR Processes.process_name=bun) (Processes.process="*/tmp/p*.js*") by Processes.dest Processes.user Processes.process_path Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe")
| where FileName == "bun" or FolderPath matches regex @"^/tmp/[^/]+/bun$"
| where ProcessCommandLine matches regex @"/tmp/p[A-Za-z0-9]+\.js\b"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Known-malicious Miasma index.js dropped to node_modules (SHA1 IOC)

`UC_11_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("8bf051251ec3b973e39a313547e53421a2f8d2f6","608d01124cd6b5b8c55888e984b4c4d9b06fa686","ab9903d9edc720d1e11ea7d3d3e7a1c456f44ff7","7569d69cf3684a792ce63d19b6e0d9d192597963")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time)
```

**Defender KQL:**
```kql
let MiasmaSHA1 = dynamic([
  "8bf051251ec3b973e39a313547e53421a2f8d2f6",
  "608d01124cd6b5b8c55888e984b4c4d9b06fa686",
  "ab9903d9edc720d1e11ea7d3d3e7a1c456f44ff7",
  "7569d69cf3684a792ce63d19b6e0d9d192597963"
]);
union isfuzzy=true
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (MiasmaSHA1)
    | project Timestamp, Source="DeviceFileEvents", DeviceName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (MiasmaSHA1)
    | project Timestamp, Source="DeviceProcessEvents", DeviceName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName=InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA1 in~ (MiasmaSHA1)
    | project Timestamp, Source="DeviceImageLoadEvents", DeviceName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine="")
| order by Timestamp desc
```

### [LLM] node process reading cloud / CI credential files during npm install

`UC_11_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name=node OR Filesystem.process_name=node.exe OR Filesystem.process_name=bun OR Filesystem.process_name=bun.exe) (Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_path="*/.aws/config*" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*/.azure/*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*/.npmrc*" OR Filesystem.file_path="*/.docker/config.json*" OR Filesystem.file_path="*/.circleci/*" OR Filesystem.file_path="*/vault/*" OR Filesystem.file_path="*/.vault-token*" OR Filesystem.file_path="*/run/secrets/kubernetes.io*" OR Filesystem.file_path="*/github/home/*" OR Filesystem.file_path="*/runner/_work/_temp/*" OR Filesystem.file_path="*GITHUB_ENV*" OR Filesystem.file_path="*GITHUB_OUTPUT*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where mvcount(paths) >= 3 | rename firstTime as first_time lastTime as last_time | convert ctime(first_time) ctime(last_time)
```

**Defender KQL:**
```kql
let CredPaths = dynamic([
  "/.aws/credentials","/.aws/config",
  "/.config/gcloud/","/.config/gcloud/credentials.db","/.config/gcloud/application_default_credentials.json",
  "/.azure/","/.azure/accessTokens.json","/.azure/azureProfile.json",
  "/.kube/config","/run/secrets/kubernetes.io",
  "/.npmrc","/.docker/config.json",
  "/.circleci/","/circleci/api_token",
  "/.vault-token","/vault/",
  "/runner/_work/_temp/_runner_file_commands","GITHUB_ENV","GITHUB_OUTPUT","actions_runner"
]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","node.exe","bun","bun.exe")
| where FolderPath has_any (CredPaths) or FileName has_any (CredPaths)
| summarize PathsTouched = make_set(strcat(FolderPath, "/", FileName), 25),
            DistinctPaths = dcount(strcat(FolderPath, "/", FileName)),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            arg_min(InitiatingProcessCommandLine, *)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessFileName
| where DistinctPaths >= 3
| order by FirstSeen desc
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

### Article-specific behavioural hunt — Red Hat Confirms Supply Chain Compromise of @redhat-cloud-services npm Packages

`UC_11_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Red Hat Confirms Supply Chain Compromise of @redhat-cloud-services npm Packages ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Red Hat Confirms Supply Chain Compromise of @redhat-cloud-services npm Packages
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8bf051251ec3b973e39a313547e53421a2f8d2f6`, `608d01124cd6b5b8c55888e984b4c4d9b06fa686`, `ab9903d9edc720d1e11ea7d3d3e7a1c456f44ff7`, `7569d69cf3684a792ce63d19b6e0d9d192597963`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
