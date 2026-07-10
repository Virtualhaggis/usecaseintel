# [HIGH] Multiple @immobiliarelabs Backstage Plugins Compromised on npm

**Source:** StepSecurity
**Published:** 2026-07-01
**Article:** https://www.stepsecurity.io/blog/immobiliarelabs-npm-packages-compromised

## Threat Profile

Back to Blog Threat Intel Multiple @immobiliarelabs Backstage Plugins Compromised on npm Compromised versions run a malicious payload at npm install time through a binding.gyp node-gyp hook, harvesting credentials from sources like GitHub Actions secrets, cloud provider keys, and package registry tokens, while trying to persist in AI coding assistant configs. Static analysis of version 2.1.2 against the clean 2.1.1 release revealed a new 5 MB index.js and an added binding.gyp, both absent from e…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-<os>-<arch>.zip`
- **SHA256:** `ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108`
- **SHA256:** `da39146ef451d1b174a24d00b1e2a45cd38d54e849737f8f35333dcb22175707`
- **SHA256:** `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1620** — Reflective Code Loading
- **T1546** — Event Triggered Execution
- **T1554** — Compromise Host Software Binary
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1552.007** — Unsecured Credentials: Container API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Phantom Gyp binding.gyp install-time payload execution (Miasma npm worm)

`UC_129_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*node index.js*" Processes.process="*echo stub.c*" by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_all ("node index.js", "echo stub.c")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### Bun runtime executing a temp payload spawned by node (Miasma Node.js-monitoring evasion)

`UC_129_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=bun Processes.parent_process_name IN (node,sh,bash,dash,npm,node-gyp) (Processes.process="*/tmp/*" OR Processes.process="*/var/folders/*") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bun" or FileName startswith "bun-"
| where InitiatingProcessFileName in~ ("node","sh","bash","dash","npm","node-gyp","yarn","pnpm")
| where ProcessCommandLine has_any ("/tmp/","/var/folders/","/var/tmp/") or FolderPath has_any ("/tmp/","/var/folders/")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Miasma infectHost persistence in AI coding assistant configs

`UC_129_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*.claude/settings.json*" OR Filesystem.file_path="*.vscode/tasks.json*" OR Filesystem.file_path="*.cursor/rules*" OR Filesystem.file_path="*.aider.conf.yml*" OR Filesystem.file_path="*copilot-instructions.md*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/.claude/settings.json", "/.vscode/tasks.json", "/.cursor/rules", "/.aider.conf.yml", "copilot-instructions.md") or FileName in~ ("settings.json","tasks.json",".aider.conf.yml","copilot-instructions.md")
| where FolderPath has_any (".claude",".vscode",".cursor",".aider.conf.yml","copilot-instructions.md")
| where InitiatingProcessFileName in~ ("node","bun","sh","bash","dash","npm","node-gyp")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Cloud instance-metadata harvesting from npm/node install context (Miasma credential theft)

`UC_129_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("169.254.169.254","169.254.170.2") All_Traffic.process_name IN (node,bun,npm,node-gyp,yarn,pnpm) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("169.254.169.254","169.254.170.2")
| where InitiatingProcessFileName in~ ("bun","node","npm","node-gyp","sh","bash","dash","yarn","pnpm")
| where InitiatingProcessFileName =~ "bun" or InitiatingProcessParentFileName in~ ("npm","node-gyp","sh","bash","dash","yarn","pnpm")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by Timestamp desc
```

### Compromised @immobiliarelabs Backstage plugin on disk (binding.gyp + index.js / known hashes)

`UC_129_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*@immobiliarelabs/backstage-plugin-gitlab*" OR Filesystem.file_path="*@immobiliarelabs/backstage-plugin-ldap-auth*") (Filesystem.file_name="binding.gyp" OR Filesystem.file_name="index.js") by Filesystem.dest Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has "@immobiliarelabs" and (FolderPath has "backstage-plugin-gitlab" or FolderPath has "backstage-plugin-ldap-auth") and FileName in~ ("binding.gyp","index.js"))
    or SHA256 in~ ("ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108","da39146ef451d1b174a24d00b1e2a45cd38d54e849737f8f35333dcb22175707","ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, FileSize, SHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — Multiple @immobiliarelabs Backstage Plugins Compromised on npm

`UC_129_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Multiple @immobiliarelabs Backstage Plugins Compromised on npm ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/home/runner/.vault-token*" OR Filesystem.file_path="*/root/.vault-token*" OR Filesystem.file_name IN ("index.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Multiple @immobiliarelabs Backstage Plugins Compromised on npm
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/dev/null", "/home/runner/.vault-token", "/root/.vault-token") or FileName in~ ("index.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/bun-<os>-<arch>.zip`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ceff7c51d70832c3ec8dd2744b606a23b3c924ef664ae23439b9b742ea154108`, `da39146ef451d1b174a24d00b1e2a45cd38d54e849737f8f35333dcb22175707`, `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
