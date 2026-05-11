# [HIGH] Hackers Use Fake DeepSeek TUI GitHub Repositories to Deliver Malware

**Source:** Cyber Security News
**Published:** 2026-05-11
**Article:** https://cybersecuritynews.com/hackers-use-fake-deepseek-tui-github-repositories/

## Threat Profile

Home Cyber Security News 
Hackers Use Fake DeepSeek TUI GitHub Repositories to Deliver Malware 
By Tushar Subhra Dutta 
May 11, 2026 




Hackers are once again targeting developers and AI enthusiasts by impersonating popular open-source tools on GitHub. This time, the target is DeepSeek TUI, a legitimate terminal-based intelligent agent that allows users to interact with DeepSeek large language models directly from the command line. 
With the recent release of DeepSeek v4 and a widely share…

## Indicators of Compromise (high-fidelity only)

- **MD5:** `b96c0d609c1b7e74f8cb1442bf0b5418`
- **MD5:** `7de2896e373342e0f3b765c855bf7396`
- **MD5:** `78c11c45c00a9c22f537c59a472beca1`
- **MD5:** `df36a31148d2c6414bdafeab771ea728`
- **MD5:** `14920c9751d20452a1006d20b8e73234`
- **MD5:** `f6d328422e7ca22e70a6aa71315450f3`
- **MD5:** `86c7f2a3c307928daaca7c1df3ea5d72`
- **MD5:** `dbaa133fd3d1a834460206d83b480f80`
- **MD5:** `22c0c7d441fd22432cfe7854b59ba82b`
- **MD5:** `a224f44bdac16250d8093df68e05b512`
- **MD5:** `6861fa47889e0340ab7efaab448c56b6`
- **MD5:** `437e4bdb12d7fa8d1c9a9e9db84b8726`
- **MD5:** `fbfe7513685913e6f878647eec429d45`
- **MD5:** `562d48524313d414b5a419fed6ca10aa`
- **MD5:** `df8a2e7aa46af996bdf67d79601671c3`
- **MD5:** `f101a346502a324320f952d39e217064`
- **MD5:** `5d14461718b74b86fdd68c6aee801dc4`
- **MD5:** `556b35236eeb111b0606d88a7aa3fd87`
- **MD5:** `ff371b43786cbb87dab325ce17cf8b7c`
- **MD5:** `1bd1df4f228ecd29a9b6fab48beaa366`
- **MD5:** `975bd8eb56716adbcadb5216592a17c7`
- **MD5:** `347980085c8926d5a1ff8e15a31fd812`
- **MD5:** `46917d8326d77e4e3c39cb843dbfc675`
- **MD5:** `b6f77b48223f57c67f00ccd8ab3d047e`
- **MD5:** `8dde7a417130ae78a3f2aeed1f5b8f58`
- **MD5:** `4c7abc81b308fc874ec0de4f026db260`
- **MD5:** `48dd212fae0086822d4ae7696cc61693`
- **MD5:** `faa5f780fb0e0786dd1a2bd19af290ca`
- **MD5:** `6721f30d84f58532d877f2b31bfc9162`
- **MD5:** `a9d492ab22400257f756f0308e06f04c`
- **MD5:** `d0a92b090279894f4628bc3d627fbde0`
- **MD5:** `397405106d895815a9bef8d84445af5a`
- **MD5:** `b7a76b82c2a5e16a3c346cc6aa145556`
- **MD5:** `f01e96a80f92c414dd824aef5a1ac1e7`
- **MD5:** `ecb3e753b60cc0f3d7de50fe7f133e49`
- **MD5:** `68ba5a1bafae7db35e2eee7ea3f11882`
- **MD5:** `e102797eb4225a93eaeeaa6b9979716a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
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
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1562.001** — Disable or Modify Tools
- **T1562.004** — Disable or Modify System Firewall
- **T1140** — Deobfuscate/Decode Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Match Legitimate Name or Location
- **T1608.001** — Stage Capabilities: Upload Malware

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ClawCode Defender disable + inbound firewall ports 57001/57002/56001 (fake DeepSeek TUI)

`UC_1_16` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="netsh.exe" Processes.process="*advfirewall*" (Processes.process="*57001*" OR Processes.process="*57002*" OR Processes.process="*56001*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") Processes.process="*New-NetFirewallRule*" (Processes.process="*57001*" OR Processes.process="*57002*" OR Processes.process="*56001*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") Processes.process="*Set-MpPreference*" (Processes.process="*DisableBehaviorMonitoring*" OR Processes.process="*MAPSReporting*" OR Processes.process="*SubmitSamplesConsent*" OR Processes.process="*DisableRealtimeMonitoring*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") Processes.process="*Add-MpPreference*" Processes.process="*ExclusionPath*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where firstTime > relative_time(now(), "-7d@d")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "netsh.exe" and ProcessCommandLine has "advfirewall" and ProcessCommandLine has_any ("57001","57002","56001"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("New-NetFirewallRule","NetFirewallRule") and ProcessCommandLine has_any ("57001","57002","56001"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has_any ("DisableBehaviorMonitoring","MAPSReporting","SubmitSamplesConsent","DisableRealtimeMonitoring","DisableIOAVProtection"))
    or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Add-MpPreference" and ProcessCommandLine has "ExclusionPath")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd   = InitiatingProcessCommandLine,
          ParentSha256 = InitiatingProcessSHA256,
          ParentFolder = InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] ClawCode C2 + Pastebin/snippet.host payload staging beacon

`UC_1_17` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*mikolirentryifosttry.info*" OR Web.url="*zkevopenanu.cfd*" OR Web.url="*hkdk.events/djbk1i9hp0sqoh*" OR Web.url="*pastebin.com/raw/w6BVFFWQ*" OR Web.url="*pastebin.com/raw/5tmHDYrf*" OR Web.url="*pastebin.com/raw/M6KthA5Z*" OR Web.url="*snippet.host/beuskq/raw*" OR Web.url="*snippet.host/uikosx/raw*") by Web.src Web.dest Web.url Web.user Web.http_user_agent Web.app | `drop_dm_object_name(Web)` | append [ | tstats `summariesonly` count from datamodel=Network_Resolution where (DNS.query="*mikolirentryifosttry.info" OR DNS.query="*zkevopenanu.cfd" OR DNS.query="*hkdk.events") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)`] | where firstTime > relative_time(now(), "-30d@d")
```

**Defender KQL:**
```kql
let ClawIndicators = dynamic([
  "mikolirentryifosttry.info","zkevopenanu.cfd",
  "hkdk.events/djbk1i9hp0sqoh",
  "pastebin.com/raw/w6BVFFWQ","pastebin.com/raw/5tmHDYrf","pastebin.com/raw/M6KthA5Z",
  "snippet.host/beuskq","snippet.host/uikosx"
]);
let ClawC2Hosts = dynamic(["mikolirentryifosttry.info","zkevopenanu.cfd","hkdk.events"]);
union isfuzzy=true
  ( DeviceNetworkEvents
      | where Timestamp > ago(30d)
      | where isnotempty(RemoteUrl)
      | where RemoteUrl has_any (ClawIndicators)
      | project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
                InitiatingProcessFileName, InitiatingProcessFolderPath,
                InitiatingProcessCommandLine, InitiatingProcessSHA256,
                Src="DeviceNetworkEvents"),
  ( DeviceEvents
      | where Timestamp > ago(30d)
      | where ActionType == "DnsQueryResponse"
      | extend QName = tolower(tostring(parse_json(AdditionalFields).QueryName))
      | where QName has_any (ClawC2Hosts)
      | project Timestamp, DeviceName, RemoteUrl=QName,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                InitiatingProcessSHA256, Src="DnsQueryResponse")
| order by Timestamp desc
```

### [LLM] ClawCode spoofed AI-tool installer hash match (DeepSeek/Claude/Grok/WormGPT/KawaiiGPT)

`UC_1_18` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_hash IN ("b96c0d609c1b7e74f8cb1442bf0b5418","7de2896e373342e0f3b765c855bf7396","78c11c45c00a9c22f537c59a472beca1","df36a31148d2c6414bdafeab771ea728","14920c9751d20452a1006d20b8e73234","f6d328422e7ca22e70a6aa71315450f3","86c7f2a3c307928daaca7c1df3ea5d72","dbaa133fd3d1a834460206d83b480f80","22c0c7d441fd22432cfe7854b59ba82b","a224f44bdac16250d8093df68e05b512","6861fa47889e0340ab7efaab448c56b6","437e4bdb12d7fa8d1c9a9e9db84b8726","fbfe7513685913e6f878647eec429d45","562d48524313d414b5a419fed6ca10aa","df8a2e7aa46af996bdf67d79601671c3","f101a346502a324320f952d39e217064","5d14461718b74b86fdd68c6aee801dc4","556b35236eeb111b0606d88a7aa3fd87","ff371b43786cbb87dab325ce17cf8b7c","1bd1df4f228ecd29a9b6fab48beaa366","975bd8eb56716adbcadb5216592a17c7","347980085c8926d5a1ff8e15a31fd812","46917d8326d77e4e3c39cb843dbfc675","b6f77b48223f57c67f00ccd8ab3d047e","8dde7a417130ae78a3f2aeed1f5b8f58","4c7abc81b308fc874ec0de4f026db260","48dd212fae0086822d4ae7696cc61693","faa5f780fb0e0786dd1a2bd19af290ca","6721f30d84f58532d877f2b31bfc9162","a9d492ab22400257f756f0308e06f04c","d0a92b090279894f4628bc3d627fbde0","397405106d895815a9bef8d84445af5a","b7a76b82c2a5e16a3c346cc6aa145556","f01e96a80f92c414dd824aef5a1ac1e7","ecb3e753b60cc0f3d7de50fe7f133e49","68ba5a1bafae7db35e2eee7ea3f11882","e102797eb4225a93eaeeaa6b9979716a") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where firstTime > relative_time(now(), "-30d@d")
```

**Defender KQL:**
```kql
let ClawHashes = dynamic([
  "b96c0d609c1b7e74f8cb1442bf0b5418","7de2896e373342e0f3b765c855bf7396",
  "78c11c45c00a9c22f537c59a472beca1","df36a31148d2c6414bdafeab771ea728",
  "14920c9751d20452a1006d20b8e73234","f6d328422e7ca22e70a6aa71315450f3",
  "86c7f2a3c307928daaca7c1df3ea5d72","dbaa133fd3d1a834460206d83b480f80",
  "22c0c7d441fd22432cfe7854b59ba82b","a224f44bdac16250d8093df68e05b512",
  "6861fa47889e0340ab7efaab448c56b6","437e4bdb12d7fa8d1c9a9e9db84b8726",
  "fbfe7513685913e6f878647eec429d45","562d48524313d414b5a419fed6ca10aa",
  "df8a2e7aa46af996bdf67d79601671c3","f101a346502a324320f952d39e217064",
  "5d14461718b74b86fdd68c6aee801dc4","556b35236eeb111b0606d88a7aa3fd87",
  "ff371b43786cbb87dab325ce17cf8b7c","1bd1df4f228ecd29a9b6fab48beaa366",
  "975bd8eb56716adbcadb5216592a17c7","347980085c8926d5a1ff8e15a31fd812",
  "46917d8326d77e4e3c39cb843dbfc675","b6f77b48223f57c67f00ccd8ab3d047e",
  "8dde7a417130ae78a3f2aeed1f5b8f58","4c7abc81b308fc874ec0de4f026db260",
  "48dd212fae0086822d4ae7696cc61693","faa5f780fb0e0786dd1a2bd19af290ca",
  "6721f30d84f58532d877f2b31bfc9162","a9d492ab22400257f756f0308e06f04c",
  "d0a92b090279894f4628bc3d627fbde0","397405106d895815a9bef8d84445af5a",
  "b7a76b82c2a5e16a3c346cc6aa145556","f01e96a80f92c414dd824aef5a1ac1e7",
  "ecb3e753b60cc0f3d7de50fe7f133e49","68ba5a1bafae7db35e2eee7ea3f11882",
  "e102797eb4225a93eaeeaa6b9979716a"]);
union isfuzzy=true
  ( DeviceProcessEvents
      | where Timestamp > ago(30d)
      | where MD5 in (ClawHashes) or InitiatingProcessMD5 in (ClawHashes)
      | project Timestamp, DeviceName, AccountName, FileName, FolderPath, MD5, SHA256,
                ProcessCommandLine,
                ParentImage = InitiatingProcessFileName,
                ParentCmd   = InitiatingProcessCommandLine,
                Src="DeviceProcessEvents"),
  ( DeviceFileEvents
      | where Timestamp > ago(30d)
      | where MD5 in (ClawHashes) or InitiatingProcessMD5 in (ClawHashes)
      | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
                FileName, FolderPath, MD5, SHA256,
                ProcessCommandLine = InitiatingProcessCommandLine,
                ParentImage = InitiatingProcessFileName,
                ParentCmd   = InitiatingProcessCommandLine,
                Src="DeviceFileEvents"),
  ( DeviceImageLoadEvents
      | where Timestamp > ago(30d)
      | where MD5 in (ClawHashes) or InitiatingProcessMD5 in (ClawHashes)
      | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
                FileName, FolderPath, MD5, SHA256,
                ProcessCommandLine = InitiatingProcessCommandLine,
                ParentImage = InitiatingProcessFileName,
                ParentCmd   = InitiatingProcessCommandLine,
                Src="DeviceImageLoadEvents")
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Hackers Use Fake DeepSeek TUI GitHub Repositories to Deliver Malware

`UC_1_15` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Use Fake DeepSeek TUI GitHub Repositories to Deliver Malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("deepseek-tui_x64.exe","onesync.exe","winhealhcare.exe","onedrive_sync.exe","svc_service.exe","autodate.exe","bbg_free_x64.exe","catgatekeeper_x64.exe","claudedesign-optimized_x64.exe","deepseek-v4-pro_x64.exe","dv4-mcp-setup.exe","fraudgpt_x64.exe","glm5-local_x64.exe","gpt-image-2-desktop.exe","grokcli_x64.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("deepseek-tui_x64.exe","onesync.exe","winhealhcare.exe","onedrive_sync.exe","svc_service.exe","autodate.exe","bbg_free_x64.exe","catgatekeeper_x64.exe","claudedesign-optimized_x64.exe","deepseek-v4-pro_x64.exe","dv4-mcp-setup.exe","fraudgpt_x64.exe","glm5-local_x64.exe","gpt-image-2-desktop.exe","grokcli_x64.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Use Fake DeepSeek TUI GitHub Repositories to Deliver Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("deepseek-tui_x64.exe", "onesync.exe", "winhealhcare.exe", "onedrive_sync.exe", "svc_service.exe", "autodate.exe", "bbg_free_x64.exe", "catgatekeeper_x64.exe", "claudedesign-optimized_x64.exe", "deepseek-v4-pro_x64.exe", "dv4-mcp-setup.exe", "fraudgpt_x64.exe", "glm5-local_x64.exe", "gpt-image-2-desktop.exe", "grokcli_x64.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("deepseek-tui_x64.exe", "onesync.exe", "winhealhcare.exe", "onedrive_sync.exe", "svc_service.exe", "autodate.exe", "bbg_free_x64.exe", "catgatekeeper_x64.exe", "claudedesign-optimized_x64.exe", "deepseek-v4-pro_x64.exe", "dv4-mcp-setup.exe", "fraudgpt_x64.exe", "glm5-local_x64.exe", "gpt-image-2-desktop.exe", "grokcli_x64.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b96c0d609c1b7e74f8cb1442bf0b5418`, `7de2896e373342e0f3b765c855bf7396`, `78c11c45c00a9c22f537c59a472beca1`, `df36a31148d2c6414bdafeab771ea728`, `14920c9751d20452a1006d20b8e73234`, `f6d328422e7ca22e70a6aa71315450f3`, `86c7f2a3c307928daaca7c1df3ea5d72`, `dbaa133fd3d1a834460206d83b480f80` _(+29 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 19 use case(s) fired, 33 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
