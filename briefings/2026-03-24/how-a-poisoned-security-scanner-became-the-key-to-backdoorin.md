# [CRIT] How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM

**Source:** Snyk
**Published:** 2026-03-24
**Article:** https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/

## Threat Profile

Snyk Blog In this article
Written by Stephen Thoemmes 
March 24, 2026
0 mins read On March 24, 2026, two versions of the litellm Python package on PyPI were found to contain malicious code. The packages (versions 1.82.7 and 1.82.8) were published by a threat actor known as TeamPCP after they obtained the maintainer's PyPI credentials through a prior compromise of Trivy, an open source security scanner used in LiteLLM's CI/CD pipeline.
The malicious versions were available for approximately three…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.11`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `checkmarx.zone`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1546.018** — Event Triggered Execution: Python Startup Hooks
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1486** — Data Encrypted for Impact (encryption step here is exfil-prep, not impact)
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious litellm 1.82.7/1.82.8 wheel install drops litellm_init.pth in site-packages

`UC_372_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name="litellm_init.pth" OR Filesystem.file_path="*litellm-1.82.7.dist-info*" OR Filesystem.file_path="*litellm-1.82.8.dist-info*" OR Filesystem.file_path="*/site-packages/litellm_init.pth") by host Filesystem.file_path Filesystem.file_name Filesystem.file_size | `drop_dm_object_name(Filesystem)` | where file_size > 30000 OR file_name="litellm_init.pth" OR file_path="*litellm-1.82.7*" OR file_path="*litellm-1.82.8*" | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "litellm_init.pth" and FolderPath has "site-packages")
   or (FolderPath has_any ("litellm-1.82.7.dist-info", "litellm-1.82.8.dist-info"))
   or (FileName =~ "litellm_init.pth" and FileSize between (30000 .. 40000))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Python .pth startup hook executes subprocess to curl C2 (litellm fork-bomb pattern)

`UC_372_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as pcmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python3","python.exe","python3.exe","pwsh.exe") AND Processes.process_name IN ("curl","curl.exe","openssl","openssl.exe","tar","tar.exe")) AND (Processes.process="*models.litellm.cloud*" OR Processes.process="*tpcp.tar.gz*" OR Processes.process="*session.key*" OR Processes.process="*payload.enc*" OR Processes.parent_process="*litellm_init.pth*") by host Processes.user Processes.process_name Processes.parent_process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python","python3","python.exe","python3.exe")
| where (FileName in~ ("curl","curl.exe","openssl","openssl.exe","tar","tar.exe"))
   and (ProcessCommandLine has_any ("models.litellm.cloud","tpcp.tar.gz","session.key","payload.enc","session.key.enc")
        or ProcessCommandLine has "AES-256-CBC" and ProcessCommandLine has "-pbkdf2")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] DNS / HTTPS egress to TeamPCP exfil infra (models.litellm.cloud, checkmarx.zone)

`UC_372_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.user) as user values(All_Traffic.src) as src from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="83.142.209.11" OR All_Traffic.dest_host="models.litellm.cloud" OR All_Traffic.dest_host="checkmarx.zone" OR All_Traffic.url="*models.litellm.cloud*" OR All_Traffic.url="*checkmarx.zone*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.url All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(60d)
  | where RemoteUrl has_any ("models.litellm.cloud","checkmarx.zone") or RemoteIP == "83.142.209.11"
  | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
),
( DeviceEvents
  | where Timestamp > ago(60d)
  | where ActionType == "DnsConnectionInspected" or ActionType has "Dns"
  | where RemoteUrl has_any ("models.litellm.cloud","checkmarx.zone") or AdditionalFields has_any ("models.litellm.cloud","checkmarx.zone")
  | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, RemoteUrl, AdditionalFields
)
| order by Timestamp desc
```

### [LLM] Exfil staging artefacts: session.key, payload.enc, session.key.enc, tpcp.tar.gz in temp

`UC_372_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("tpcp.tar.gz","session.key","session.key.enc","payload.enc") by host Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | stats min(firstTime) as firstTime max(lastTime) as lastTime values(file_name) as files dc(file_name) as distinct_files values(file_path) as paths values(proc) as procs by host user | where distinct_files >= 2 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("tpcp.tar.gz","session.key","session.key.enc","payload.enc")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Files=make_set(FileName), DistinctFiles=dcount(FileName),
            Procs=make_set(InitiatingProcessFileName),
            CmdLines=make_set(InitiatingProcessCommandLine),
            Paths=make_set(FolderPath)
          by DeviceName, InitiatingProcessAccountName
| where DistinctFiles >= 2 or array_index_of(Files, "tpcp.tar.gz") >= 0
| order by FirstSeen desc
```

### [LLM] TeamPCP Linux credential harvest: Python reading /etc/shadow + auth.log + cloud

`UC_372_13` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("python","python3") AND (Filesystem.file_path="/etc/shadow" OR Filesystem.file_path="/var/log/auth.log" OR Filesystem.file_path="*/.ssh/id_*" OR Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.aws/config" OR Filesystem.file_path="*/.azure/*" OR Filesystem.file_path="*/.config/gcloud/*" OR Filesystem.file_path="*/.kube/config" OR Filesystem.file_path="*/.docker/config.json" OR Filesystem.file_path="*/.env" OR Filesystem.file_path="*/wallet.dat" OR Filesystem.file_path="*/.bitcoin/*" OR Filesystem.file_path="*/.ethereum/keystore/*") by host Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)` | stats min(firstTime) as firstTime values(paths) as touched_paths dc(file_path) as distinct_sensitive_paths by host user process_name | where distinct_sensitive_paths >= 3 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let SensitivePaths = dynamic([
    "/etc/shadow", "/var/log/auth.log",
    "/.ssh/id_", "/.ssh/authorized_keys",
    "/.aws/credentials", "/.aws/config",
    "/.azure/", "/.config/gcloud/",
    "/.kube/config", "/.docker/config.json",
    "/.env", "wallet.dat", "/.bitcoin/", "/.ethereum/keystore/", "/.solana/", "/.cardano/", "/Ledger/"
  ]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python","python3")
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileAccessed")
   or ActionType has "File"
| extend MatchedPath = tostring(SensitivePaths[0])
| extend Hits = array_length(set_intersect(SensitivePaths, pack_array(FolderPath)))
| where FolderPath has_any (SensitivePaths) or FileName has_any ("shadow","auth.log","credentials","kubeconfig","wallet.dat")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            DistinctSensitivePaths=dcount(FolderPath),
            PathsSample=make_set(FolderPath, 25),
            Cmd=any(InitiatingProcessCommandLine)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessId
| where DistinctSensitivePaths >= 3
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

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM

`UC_372_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("proxy_server.py","sysmon.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/log/auth.log*" OR Filesystem.file_path="*/etc/shadow*" OR Filesystem.file_path="*/root/.config/sysmon/sysmon.py*" OR Filesystem.file_path="*/tmp/pglog*" OR Filesystem.file_path="*/tmp/.pg_state*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_path="*/tmp/tpcp.tar.gz*" OR Filesystem.file_path="*/tmp/session.key*" OR Filesystem.file_name IN ("proxy_server.py","sysmon.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — How a Poisoned Security Scanner Became the Key to Backdooring LiteLLM
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("proxy_server.py", "sysmon.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/log/auth.log", "/etc/shadow", "/root/.config/sysmon/sysmon.py", "/tmp/pglog", "/tmp/.pg_state", "/dev/null", "/tmp/tpcp.tar.gz", "/tmp/session.key") or FileName in~ ("proxy_server.py", "sysmon.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.11`, `models.litellm.cloud`, `checkmarx.zone`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
