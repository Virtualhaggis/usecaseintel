# [CRIT] TeamPCP Linked To Redis Attacks Dating Back To 2020 And Later Supply Chain Campaign

**Source:** The Hacker News
**Published:** 2026-08-07
**Article:** https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html

## Threat Profile

TeamPCP Linked To Redis Attacks Dating Back To 2020 And Later Supply Chain Campaign 
 Ravie Lakshmanan  Aug 07, 2026 Cybercrime / Vulnerability 
A new analysis has uncovered that the threat actor tracked as TeamPCP has been active on the cybercrime scene as far back as 2020, indicating the group has been compromising internet-facing infrastructure for years before training their sights on the software supply chain.
"The connection is supported by overlapping domains, malware deployment paths, …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2025-66478`
- **IPv4 (defanged):** `23.142.184.129`
- **IPv4 (defanged):** `45.148.10.212`
- **IPv4 (defanged):** `63.251.162.11`
- **IPv4 (defanged):** `83.142.209.11`
- **IPv4 (defanged):** `83.142.209.203`
- **IPv4 (defanged):** `195.5.171.242`
- **IPv4 (defanged):** `209.34.235.18`
- **IPv4 (defanged):** `212.71.124.188`
- **IPv4 (defanged):** `67.217.57.240`
- **Domain (defanged):** `masscan.cloud`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `models.litellm.cloud`
- **Domain (defanged):** `scan.aquasecurtiy.org`
- **Domain (defanged):** `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
- **Domain (defanged):** `championships-peoples-point-cassette.trycloudflare.com`
- **Domain (defanged):** `create-sensitivity-grad-sequence.trycloudflare.com`
- **Domain (defanged):** `investigation-launches-hearings-copying.trycloudflare.com`
- **Domain (defanged):** `plug-tab-protective-relay.trycloudflare.com`
- **Domain (defanged):** `souls-entire-defined-routes.trycloudflare.com`
- **SHA256:** `0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349`
- **SHA256:** `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a`
- **SHA256:** `0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f`
- **SHA256:** `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a`
- **SHA256:** `1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb`
- **SHA256:** `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956`
- **SHA256:** `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba`
- **SHA256:** `6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538`
- **SHA256:** `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9`
- **SHA256:** `7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca`
- **SHA256:** `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7`
- **SHA256:** `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0`
- **SHA256:** `887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073`
- **SHA256:** `bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7`
- **SHA256:** `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926`
- **SHA256:** `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3`
- **SHA256:** `d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c`
- **SHA256:** `e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea`
- **SHA256:** `e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243`
- **SHA256:** `e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf`
- **SHA256:** `e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49`
- **SHA256:** `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b`
- **SHA256:** `ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c`
- **SHA256:** `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152`
- **SHA256:** `f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1053.003** — Scheduled Task/Job: Cron
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1102** — Web Service
- **T1610** — Deploy Container
- **T1485** — Data Destruction
- **T1489** — Service Stop
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1222.002** — File and Directory Permissions Modification: Linux
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1546.013** — Event Triggered Execution: systemd

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Redis-server RCE: redis-server spawns shell / cron write (TeamPCP TA-NATALSTATUS)

`UC_21_14` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="redis-server" (Processes.process_name IN ("sh","bash","dash","curl","wget","python","python3","chmod","crontab","chattr") OR Processes.process IN ("*/var/spool/cron*","*/etc/crontab*","*/etc/rc.local*","*chmod +x*","*ld.so.preload*","*--no-preserve-root*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "redis-server"
| where FileName in~ ("sh","bash","dash","curl","wget","python","python3","chmod","crontab","chattr")
    or ProcessCommandLine has_any ("/var/spool/cron","/etc/crontab","/etc/rc.local","chmod +x","ld.so.preload","--no-preserve-root")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### TeamPCP kube.py / kamikaze.sh stager pulled from Cloudflare tunnel

`UC_21_15` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("curl","wget","python","python3","sh","bash") (Processes.process IN ("*kamikaze.sh*","*kube.py*","*prop.py*") OR Processes.process IN ("*souls-entire-defined-routes.trycloudflare.com*","*investigation-launches-hearings-copying.trycloudflare.com*","*championships-peoples-point-cassette.trycloudflare.com*","*create-sensitivity-grad-sequence.trycloudflare.com*","*plug-tab-protective-relay.trycloudflare.com*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("curl","wget","python","python3","sh","bash")
| where ProcessCommandLine has_any ("kamikaze.sh","kube.py","prop.py")
    or ProcessCommandLine has_any ("souls-entire-defined-routes.trycloudflare.com","investigation-launches-hearings-copying.trycloudflare.com","championships-peoples-point-cassette.trycloudflare.com","create-sensitivity-grad-sequence.trycloudflare.com","plug-tab-protective-relay.trycloudflare.com")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, FolderPath, SHA256
| order by Timestamp desc
```

### TeamPCP destructive Kubernetes DaemonSet (Kamikaze wiper) — Iran-gated node wipe

`UC_21_16` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*chroot /mnt/host reboot*" OR (Processes.process="*/mnt/host*" AND Processes.process="*rm -rf*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "chroot /mnt/host reboot"
    or (ProcessCommandLine has "/mnt/host" and ProcessCommandLine has "rm -rf" and ProcessCommandLine has "-maxdepth 1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### TeamPCP C2 egress — trycloudflare tunnels, ICP canister, masscan.cloud & typosquat domains

`UC_21_17` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("masscan.cloud","scan.aquasecurtiy.org","checkmarx.zone","models.litellm.cloud","tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io","championships-peoples-point-cassette.trycloudflare.com","create-sensitivity-grad-sequence.trycloudflare.com","investigation-launches-hearings-copying.trycloudflare.com","plug-tab-protective-relay.trycloudflare.com","souls-entire-defined-routes.trycloudflare.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let c2Domains = dynamic(["masscan.cloud","scan.aquasecurtiy.org","checkmarx.zone","models.litellm.cloud","tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io","championships-peoples-point-cassette.trycloudflare.com","create-sensitivity-grad-sequence.trycloudflare.com","investigation-launches-hearings-copying.trycloudflare.com","plug-tab-protective-relay.trycloudflare.com","souls-entire-defined-routes.trycloudflare.com"]);
let c2Ips = dynamic(["23.142.184.129","45.148.10.212","63.251.162.11","83.142.209.11","83.142.209.203","195.5.171.242","209.34.235.18","212.71.124.188","67.217.57.240"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (c2Domains) or RemoteIP in (c2Ips)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Linux userland-rootkit persistence — ld.so.preload + chattr immutability + admin-tool masquerade

`UC_21_18` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ( (Processes.process_name="chattr" AND Processes.process="*+i*") OR (Processes.process="*/etc/ld.so.preload*") OR (Processes.process_name IN ("mv","cp") AND (Processes.process="*/bin/ps*" OR Processes.process="*/usr/bin/top*" OR Processes.process="*/usr/bin/curl*" OR Processes.process="*/usr/bin/wget*")) ) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "chattr" and ProcessCommandLine has "+i")
    or ProcessCommandLine has "/etc/ld.so.preload"
    or (FileName in~ ("mv","cp") and ProcessCommandLine has_any ("/bin/ps","/usr/bin/top","/usr/bin/curl","/usr/bin/wget"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### TeamPCP poison_pill filesystem destruction — rm -rf / --no-preserve-root

`UC_21_19` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*--no-preserve-root*" (Processes.process="*rm -rf*" OR Processes.process="*rm -fr*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "--no-preserve-root"
| where ProcessCommandLine has_any ("rm -rf /","rm -fr /")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### TeamPCP supply-chain poisoned CI runner — trivy-action token theft to typosquat + tpcp staging

`UC_21_20` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="tpcp.tar.gz" OR Filesystem.file_path="*/.config/systemd/user/sysmon.py" OR Filesystem.file_path="*/tmp/pglog") by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FileName =~ "tpcp.tar.gz"
    or FolderPath has "/.config/systemd/user/sysmon.py"
    or FolderPath endswith "/tmp/pglog"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
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

### Article-specific behavioural hunt — TeamPCP Linked To Redis Attacks Dating Back To 2020 And Later Supply Chain Campa

`UC_21_13` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — TeamPCP Linked To Redis Attacks Dating Back To 2020 And Later Supply Chain Campa ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js","kube.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js","kube.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — TeamPCP Linked To Redis Attacks Dating Back To 2020 And Later Supply Chain Campa
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js", "kube.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js", "kube.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.142.184.129`, `45.148.10.212`, `63.251.162.11`, `83.142.209.11`, `83.142.209.203`, `195.5.171.242`, `209.34.235.18`, `212.71.124.188` _(+11 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`, `CVE-2025-66478`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349`, `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a`, `0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f`, `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a`, `1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb`, `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956`, `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba`, `6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538` _(+17 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 21 use case(s) fired, 37 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
