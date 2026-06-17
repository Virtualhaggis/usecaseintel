# [CRIT] LangGraph Flaw Chain Exposes Self-Hosted AI Agents to Remote Code Execution

**Source:** The Hacker News
**Published:** 2026-06-12
**Article:** https://thehackernews.com/2026/06/langgraph-flaw-chain-exposes-self.html

## Threat Profile

LangGraph Flaw Chain Exposes Self-Hosted AI Agents to Remote Code Execution 
 Ravie Lakshmanan  Jun 12, 2026 Vulnerability / AI Security 
Cybersecurity researchers have disclosed details of three now-patched security flaws impacting LangGraph , including a critical vulnerability chain that could result in remote code execution.
LangGraph is an open-source framework created by LangChain to build complex, stateful, and multi-agent artificial intelligence (AI) agentic applications.
"An SQL inject…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-67644`
- **CVE:** `CVE-2026-28277`
- **CVE:** `CVE-2026-27022`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1203** — Exploitation for Client Execution
- **T1592.002** — Gather Victim Host Information: Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1098.004** — Account Manipulation: SSH Authorized Keys

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### LangGraph get_state_history SQLi via metadata filter (CVE-2025-67644)

`UC_75_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*get_state_history*" AND Web.url="*filter*" AND (Web.url="*UNION*" OR Web.url="*SELECT*" OR Web.url="*%27*" OR Web.url="*--*" OR Web.url="*DROP*" OR Web.url="*sqlite_master*") by Web.src Web.dest Web.url Web.http_method Web.status
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### Shell/LOLBin spawned by LangGraph Python or Node runtime

`UC_75_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe","node.exe","node") AND (Processes.parent_process IN ("*langgraph*","*langchain*","*checkpoint*") OR Processes.process IN ("*langgraph*","*langchain*","*checkpoint*")) AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh","bash","curl.exe","wget.exe","curl","wget","nc","ncat.exe","certutil.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe","node.exe","node")
| where InitiatingProcessCommandLine has_any ("langgraph","langchain","checkpoint","get_state_history")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","bash.exe","sh","bash","curl.exe","wget.exe","curl","wget","nc","ncat.exe","certutil.exe","chmod","chmod.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Vulnerable langgraph / langgraph-checkpoint package version inventory

`UC_75_8` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2025-67644","CVE-2026-28277","CVE-2026-27022") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.cvss
| `drop_dm_object_name(Vulnerabilities)`
| sort - cvss
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "langgraph"
| extend Vulnerable = case(
    SoftwareName has "langgraph-checkpoint-sqlite" and SoftwareVersion matches regex @"^([0-2]\.|3\.0\.0$)", "CVE-2025-67644",
    SoftwareName has "langgraph-checkpoint-redis"  and SoftwareVersion matches regex @"^(0\.|1\.0\.0$)",   "CVE-2026-27022",
    SoftwareName == "langgraph"                    and SoftwareVersion matches regex @"^1\.0\.[0-9]$",     "CVE-2026-28277",
    "")
| where isnotempty(Vulnerable)
| project DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, Vulnerable
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId) on DeviceId
| order by IsInternetFacing desc, DeviceName asc
```

### Outbound public network from LangGraph runtime to non-allowlisted destination

`UC_75_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("python.exe","python3.exe","python","python3","uvicorn","uvicorn.exe","node.exe","node") AND All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| search dest!="*.pypi.org" dest!="*.pythonhosted.org" dest!="*.openai.com" dest!="*.anthropic.com" dest!="*.huggingface.co" dest!="*.githubusercontent.com"
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe","node.exe","node")
| where InitiatingProcessCommandLine has_any ("langgraph","langchain","checkpoint")
| where RemoteIPType == "Public"
| where RemoteUrl !endswith "pypi.org"
   and RemoteUrl !endswith "files.pythonhosted.org"
   and RemoteUrl !endswith "openai.com"
   and RemoteUrl !endswith "anthropic.com"
   and RemoteUrl !endswith "huggingface.co"
   and RemoteUrl !endswith "githubusercontent.com"
   and RemoteUrl !endswith "github.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### File writes to sensitive paths by LangGraph Python/Node runtime

`UC_75_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe","node.exe","node") AND Filesystem.action IN ("created","modified") AND (Filesystem.file_path IN ("*\\Windows\\Temp\\*","*\\Users\\Public\\*","*\\ProgramData\\*","*\\Startup\\*","/tmp/*","/var/tmp/*","/etc/cron*","/root/.ssh/*","*/.ssh/authorized_keys","*/.bashrc","*/.bash_profile","*/.profile")) by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","pythonw.exe","python","python3","uvicorn","uvicorn.exe","node.exe","node")
| where InitiatingProcessCommandLine has_any ("langgraph","langchain","checkpoint","get_state_history")
| where (FolderPath has_any (@"\Windows\Temp\", @"\Users\Public\", @"\ProgramData\", @"\Start Menu\Programs\Startup", "/tmp/", "/var/tmp/", "/etc/cron", "/root/.ssh/", "/.ssh/", "/etc/systemd/system/"))
   or FileName in~ ("authorized_keys",".bashrc",".bash_profile",".profile",".zshrc")
   or FileName endswith ".sh" or FileName endswith ".py" or FileName endswith ".dll" or FileName endswith ".exe" or FileName endswith ".so"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, SHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-67644`, `CVE-2026-28277`, `CVE-2026-27022`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
