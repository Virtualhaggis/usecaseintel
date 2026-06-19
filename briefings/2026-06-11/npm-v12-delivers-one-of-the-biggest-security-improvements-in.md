# [HIGH] npm v12 delivers one of the biggest security improvements in years

**Source:** Aikido
**Published:** 2026-06-11
**Article:** https://www.aikido.dev/blog/npm-v12-block-postinstall

## Threat Profile

Blog News npm v12 delivers one of the biggest security improvements in years npm v12 delivers one of the biggest security improvements in years Written by Dania Durnas Published on: Jun 11, 2026 npm's next major release, v12, scheduled to land July 2026 , will stop running dependency install scripts by default. 
We’re relieved to hear it. Turning off install scripts is the most useful change npm could make to its defaults. The community suffered a barrage of supply chain attacks in the last year…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.11.206.73`
- **Domain (defanged):** `sfrclak.com`
- **Domain (defanged):** `webhook.site`
- **SHA256:** `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **SHA256:** `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`
- **SHA256:** `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
- **SHA256:** `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`
- **SHA256:** `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- **SHA256:** `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`
- **SHA256:** `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- **SHA256:** `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`
- **SHA1:** `2553649f2322049666871cea80a5d0d6adc700ca`
- **SHA1:** `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`
- **SHA1:** `07d889e2dadce6f3910dcbc253317d28ca61c766`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Private Keys
- **T1567.001** — Exfiltration to Code Repository
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1105** — Ingress Tool Transfer
- **T1059** — Command and Scripting Interpreter
- **T1027.004** — Compile After Delivery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Nx s1ngularity 'telemetry.js' postinstall payload execution

`UC_152_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd","npx.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","bun.exe")) AND (Processes.process="*telemetry.js*" OR Processes.process="*s1ngularity*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","npx.cmd","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","bun.exe")
    or InitiatingProcessParentFileName in~ ("node.exe","npm.cmd","npm.exe")
| where ProcessCommandLine has "telemetry.js" or ProcessCommandLine has_any ("s1ngularity","@nrwl/nx","nx-cloud")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### TruffleHog secret scanner spawned by Node/npm (Shai-Hulud worm pattern)

`UC_152_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd","npx.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","bun.exe","node","npm","npx","yarn","pnpm","bun")) AND (Processes.process_name IN ("trufflehog","trufflehog.exe") OR Processes.process="*trufflehog*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has "trufflehog" or ProcessCommandLine has "trufflehog"
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","npx.cmd","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","bun.exe","sh.exe","bash.exe")
    or InitiatingProcessParentFileName in~ ("node.exe","npm.cmd","npm.exe","yarn.cmd","pnpm.cmd","bun.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Nx s1ngularity exfil: GitHub repo 's1ngularity-repository' / 'results.b64'

`UC_152_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("gh.exe","git.exe","curl.exe","wget.exe","gh","git")) AND (Processes.process="*s1ngularity-repository*" OR Processes.process="*results.b64*" OR (Processes.process="*repo create*" AND Processes.process="*--public*" AND Processes.process="*s1ngularity*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("gh.exe","git.exe","curl.exe","wget.exe","powershell.exe","pwsh.exe")
    | where ProcessCommandLine has_any ("s1ngularity-repository","results.b64")
        or (ProcessCommandLine has "repo create" and ProcessCommandLine has "--public" and ProcessCommandLine has "s1ngularity")
    | project Timestamp, DeviceName, AccountName,
              ActionType = "ProcessCreated",
              Evidence = strcat(FileName, " :: ", ProcessCommandLine),
              InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "results.b64" or FolderPath has "s1ngularity-repository"
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ActionType,
              Evidence = strcat(FolderPath, "\\", FileName),
              InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### Shai-Hulud Webhook.site C2 beacon from Node/npm/Bun process

`UC_152_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*webhook.site*" AND (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd","yarn.exe","pnpm.exe","bun.exe","node","npm","yarn","pnpm","bun") OR Processes.process_name IN ("node.exe","npm.exe","yarn.exe","pnpm.exe","bun.exe","curl.exe","wget.exe"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | eval shai_hulud = if(match(process, "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"), "TRUE", "FALSE") | sort 0 - shai_hulud firstTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "webhook.site"
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","npx.cmd","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","bun.exe","curl.exe","wget.exe","powershell.exe","pwsh.exe")
    or InitiatingProcessParentFileName in~ ("node.exe","npm.cmd","npm.exe","yarn.cmd","pnpm.cmd","bun.exe")
| extend ShaiHuludMarker = iff(RemoteUrl has "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7", "TRUE", "FALSE")
| project Timestamp, DeviceName,
          AccountName = InitiatingProcessAccountName,
          RemoteUrl, ShaiHuludMarker, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by ShaiHuludMarker desc, Timestamp desc
```

### Bun runtime fetched mid-npm-install (Shai-Hulud / Mini Shai-Hulud staging)

`UC_152_13` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd","npx.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","node","npm","yarn","pnpm")) AND (Processes.process="*bun.sh/install*" OR Processes.process="*oven-sh/bun*" OR (Processes.process="*curl*" AND Processes.process="*install.sh*" AND Processes.process="*bun*") OR Processes.process_name IN ("bun.exe","bun")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let JsPkgMgr = dynamic(["node.exe","npm.cmd","npm.exe","npx.cmd","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe"]);
let BunSignals = dynamic(["bun.sh/install","oven-sh/bun","install.sh"]);
union
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ (JsPkgMgr)
        or InitiatingProcessParentFileName in~ (JsPkgMgr)
    | where ProcessCommandLine has_any (BunSignals) or FileName in~ ("bun.exe","bun")
    | where AccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName,
              Source = "Process",
              Evidence = strcat(FileName, " :: ", ProcessCommandLine),
              InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any ("bun.sh/install","oven-sh/bun")
    | where InitiatingProcessFileName in~ (JsPkgMgr) or InitiatingProcessFileName in~ ("curl.exe","wget.exe","powershell.exe","pwsh.exe")
        or InitiatingProcessParentFileName in~ (JsPkgMgr)
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              Source = "Network",
              Evidence = RemoteUrl,
              InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### Implicit node-gyp rebuild from binding.gyp during npm install

`UC_152_14` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as sample_cmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","npm.exe","npm.cmd","npx.cmd","yarn.exe","yarn.cmd","pnpm.exe","pnpm.cmd","bun.exe")) AND (Processes.process="*node-gyp*rebuild*" OR Processes.process="*binding.gyp*" OR Processes.process_name IN ("node-gyp.cmd","node-gyp.exe")) by Processes.dest Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | rex field=sample_cmd "node_modules[\\\\/]+(?<native_module>[^\\\\/]+)" | stats min(firstTime) as firstTime max(lastTime) as lastTime values(native_module) as native_modules by dest user parent_process_name | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "node-gyp" and ProcessCommandLine has "rebuild")
    or ProcessCommandLine has "binding.gyp"
    or FileName in~ ("node-gyp.cmd","node-gyp.exe")
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","npm.exe","npx.cmd","yarn.cmd","yarn.exe","pnpm.cmd","pnpm.exe","bun.exe")
    or InitiatingProcessParentFileName in~ ("node.exe","npm.cmd","npm.exe")
| where AccountName !endswith "$"
| extend NativeModule = extract(@"node_modules[\\/]+([^\\/]+)", 1, ProcessCommandLine)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Hits = count(),
            DistinctModules = dcount(NativeModule),
            SampleModules = make_set(NativeModule, 25),
            SampleCmd = any(ProcessCommandLine)
            by DeviceName, AccountName
| order by FirstSeen desc
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

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — npm v12 delivers one of the biggest security improvements in years

`UC_152_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — npm v12 delivers one of the biggest security improvements in years ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("telemetry.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("telemetry.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — npm v12 delivers one of the biggest security improvements in years
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("telemetry.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("telemetry.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.206.73`, `sfrclak.com`, `webhook.site`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`, `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`, `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`, `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`, `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`, `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a` _(+3 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
