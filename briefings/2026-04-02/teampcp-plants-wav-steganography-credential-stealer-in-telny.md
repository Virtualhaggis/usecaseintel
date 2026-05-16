# [CRIT] TeamPCP Plants WAV Steganography Credential Stealer in telnyx PyPI Package

**Source:** StepSecurity
**Published:** 2026-04-02
**Article:** https://www.stepsecurity.io/blog/teampcp-plants-wav-steganography-credential-stealer-in-telnyx-pypi-package

## Threat Profile

Back to Blog Threat Intel TeamPCP Plants WAV Steganography Credential Stealer in telnyx PyPI Package On March 27, 2026, TeamPCP injected a WAV steganography-based credential stealer into two releases of the telnyx Python SDK on PyPI. The issue was disclosed in team-telnyx/telnyx-python#235. TeamPCP is the same group behind the litellm supply chain compromise three days earlier, identified by a shared RSA-4096 public key, identical encryption scheme, and the tpcp.tar.gz exfiltration signature pre…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `83.142.209.203`
- **SHA256:** `f66c1ea3b25ec95d0c6a07be92c761551e543a7b256f9c78a2ff781c77df7093`
- **SHA256:** `a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1547.001** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1001.002** — Data Obfuscation: Steganography
- **T1041** — Exfiltration Over C2 Channel
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TeamPCP C2 beacon to 83.142.209.203:8080 (telnyx/litellm WAV stego campaign)

`UC_311_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="83.142.209.203" OR All_Traffic.dest_ip="83.142.209.203") AND All_Traffic.dest_port=8080 by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | append [| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="http://83.142.209.203:8080/ringtone.wav" OR Web.url="http://83.142.209.203:8080/hangup.wav" OR Web.url="http://83.142.209.203:8080/*" OR Web.dest="83.142.209.203") by Web.src Web.user Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "83.142.209.203"
| where RemotePort == 8080 or isempty(tostring(RemotePort))
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] TeamPCP msbuild.exe LOLBin masquerade dropped to user Startup folder

`UC_311_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as creating_process values(Filesystem.user) as user values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_name="msbuild.exe" OR Filesystem.file_name="msbuild.exe.lock" OR Filesystem.file_name="msbuild.exe.tmp") AND Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | eval campaign="TeamPCP-telnyx-PyPI-2026"
```

**Defender KQL:**
```kql
let _campaign_hashes = dynamic(["f66c1ea3b25ec95d0c6a07be92c761551e543a7b256f9c78a2ff781c77df7093",
                              "a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| where (FileName =~ "msbuild.exe" or FileName =~ "msbuild.exe.lock" or FileName =~ "msbuild.exe.tmp")
| where FolderPath has @"\Microsoft\Windows\Start Menu\Programs\Startup"
| extend HashHit = iif(SHA256 in (_campaign_hashes), "TeamPCP-known-hash", "")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, HashHit,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] TeamPCP exfiltration signature: tpcp.tar.gz / X-Filename header / openssl OAEP chain

`UC_311_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.parent_process_name) as parent_process values(Processes.process) as process from datamodel=Endpoint.Processes where ( Processes.process="*tpcp.tar.gz*" OR Processes.process="*X-Filename: tpcp.tar.gz*" OR (Processes.process_name="curl" AND Processes.process="*83.142.209.203*" AND Processes.process="*8080*") OR (Processes.process_name="openssl" AND Processes.process="*pkeyutl*" AND Processes.process="*rsa_padding_mode:oaep*") OR (Processes.parent_process_name IN ("python","python3","python3.10","python3.11","python3.12") AND Processes.process="*import base64*" AND Processes.process="*exec(base64.b64decode*") ) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where
    // (a) Direct exfil signature — tpcp.tar.gz token in any cmdline
    ProcessCommandLine has "tpcp.tar.gz"
    // (b) curl POST to TeamPCP C2 IP+port
    or (FileName =~ "curl" and ProcessCommandLine has "83.142.209.203" and ProcessCommandLine has "8080")
    // (c) openssl RSA-OAEP wrap of an AES key — TeamPCP hybrid scheme
    or (FileName =~ "openssl" and ProcessCommandLine has "pkeyutl" and ProcessCommandLine has "rsa_padding_mode:oaep")
    // (d) Python -c base64 exec — the FetchAudio() launcher pattern
    or (FileName matches regex @"(?i)python(3(\.\d+)?)?$" and ProcessCommandLine has "-c" and ProcessCommandLine has "base64.b64decode" and ProcessCommandLine has "exec(")
| extend Signal = case(
    ProcessCommandLine has "tpcp.tar.gz", "tpcp_tarball",
    FileName =~ "openssl" and ProcessCommandLine has "rsa_padding_mode:oaep", "openssl_RSA_OAEP_wrap",
    FileName =~ "curl" and ProcessCommandLine has "83.142.209.203", "curl_to_C2",
    "python_b64_exec_launcher")
| project Timestamp, DeviceName, AccountName, Signal, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
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

### Article-specific behavioural hunt — TeamPCP Plants WAV Steganography Credential Stealer in telnyx PyPI Package

`UC_311_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — TeamPCP Plants WAV Steganography Credential Stealer in telnyx PyPI Package ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("msbuild.exe") OR Processes.process_path="*%APPDATA%\Microsoft\Windows\Start*" OR Processes.process_path="*%APPDATA%\...\Startup\msbuild.exe.lock*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%APPDATA%\Microsoft\Windows\Start*" OR Filesystem.file_path="*%APPDATA%\...\Startup\msbuild.exe.lock*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("msbuild.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — TeamPCP Plants WAV Steganography Credential Stealer in telnyx PyPI Package
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("msbuild.exe") or FolderPath has_any ("%APPDATA%\Microsoft\Windows\Start", "%APPDATA%\...\Startup\msbuild.exe.lock"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%APPDATA%\Microsoft\Windows\Start", "%APPDATA%\...\Startup\msbuild.exe.lock", "/dev/null") or FileName in~ ("msbuild.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `83.142.209.203`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f66c1ea3b25ec95d0c6a07be92c761551e543a7b256f9c78a2ff781c77df7093`, `a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
