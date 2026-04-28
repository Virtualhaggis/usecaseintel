# [CRIT] Weaponizing the Protectors: TeamPCP’s Multi-Stage Supply Chain Attack on Security Infrastructure

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-03-31
**Article:** https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/

## Threat Profile

Threat Research Center 
High Profile Threats 
Malware 
Malware 
Weaponizing the Protectors: TeamPCP’s Multi-Stage Supply Chain Attack on Security Infrastructure 
14 min read 
Related Products Advanced DNS Security Advanced URL Filtering Advanced WildFire Cloud-Delivered Security Services Cortex Cortex Cloud Cortex XDR Cortex Xpanse Cortex XSIAM Unit 42 Cloud Security Assessment Unit 42 Incident Response 
By: Unit 42 
Published: March 31, 2026 
Categories: High Profile Threats 
Malware 
Tags: CVE…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **SHA256:** `30015DD1E2CF4DBD49FFF9DDEF2AD4622DA2E60E5C0B6228595325532E948F14`
- **SHA256:** `41C4F2F37C0B257D1E20FE167F2098DA9D2E0A939B09ED3F63BC4FE010F8365C`
- **SHA256:** `D8CAF4581C9F0000C7568D78FB7D2E595AB36134E2346297D78615942CBBD727`
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
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Network connections to article IPs / domains

`UC_NETWORK_IOC` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest IN ("0.0.0.0")
    by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| append
    [| tstats `summariesonly` count from datamodel=Web
        where Web.dest IN ("example.invalid")
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN ("example.invalid")
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("0.0.0.0") or RemoteUrl has_any ("example.invalid")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where FolderPath has_any ("\Ethereum\keystore\","\Bitcoin\","\Exodus\","\Electrum\wallets\","\MetaMask\","\Phantom\","\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Asset exposure — vulnerability matches article CVE(s)

`_uc` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN ("CVE-2025-55182")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("CVE-2025-55182")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Suspicious URL click in email — phishing landing page

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered" AND All_Email.url!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.url, All_Email.subject
| rex field=All_Email.url "https?://(?<email_domain>[^/]+)"
| join type=inner email_domain
    [| tstats `summariesonly` count
        from datamodel=Web
        where Web.action="allowed"
        by Web.src, Web.dest, Web.url, Web.user
     | rex field=Web.url "https?://(?<email_domain>[^/]+)"]
| stats values(All_Email.subject) as subject, values(Web.url) as clicked_url,
        earliest(_time) as first_seen, latest(_time) as last_seen
        by All_Email.recipient, email_domain
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let DeliveredEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTimestamp = Timestamp;
EmailUrlInfo
| where Timestamp > ago(LookbackDays)
| join kind=inner DeliveredEmails on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | project Url, ClickTimestamp = Timestamp, AccountUpn, IPAddress
  ) on Url
| project ClickTimestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, IPAddress
| order by ClickTimestamp desc
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
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### File hash IOCs — endpoint file/process match

`UC_HASH_IOC` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN ("30015DD1E2CF4DBD49FFF9DDEF2AD4622DA2E60E5C0B6228595325532E948F14", "41C4F2F37C0B257D1E20FE167F2098DA9D2E0A939B09ED3F63BC4FE010F8365C", "D8CAF4581C9F0000C7568D78FB7D2E595AB36134E2346297D78615942CBBD727", "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349", "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a", "0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f", "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a", "1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb", "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956", "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba", "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538", "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9", "7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca", "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7", "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0", "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073", "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7", "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926", "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3", "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c", "e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea", "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243", "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf", "e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49", "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b", "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c", "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152", "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d")
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN ("30015DD1E2CF4DBD49FFF9DDEF2AD4622DA2E60E5C0B6228595325532E948F14", "41C4F2F37C0B257D1E20FE167F2098DA9D2E0A939B09ED3F63BC4FE010F8365C", "D8CAF4581C9F0000C7568D78FB7D2E595AB36134E2346297D78615942CBBD727", "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349", "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a", "0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f", "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a", "1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb", "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956", "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba", "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538", "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9", "7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca", "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7", "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0", "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073", "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7", "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926", "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3", "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c", "e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea", "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243", "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf", "e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49", "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b", "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c", "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152", "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d")
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash
     | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ ("30015DD1E2CF4DBD49FFF9DDEF2AD4622DA2E60E5C0B6228595325532E948F14", "41C4F2F37C0B257D1E20FE167F2098DA9D2E0A939B09ED3F63BC4FE010F8365C", "D8CAF4581C9F0000C7568D78FB7D2E595AB36134E2346297D78615942CBBD727", "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349", "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a", "0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f", "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a", "1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb", "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956", "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba", "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538", "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9", "7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca", "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7", "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0", "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073", "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7", "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926", "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3", "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c", "e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea", "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243", "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf", "e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49", "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b", "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c", "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152", "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d") or SHA1 in~ ("30015DD1E2CF4DBD49FFF9DDEF2AD4622DA2E60E5C0B6228595325532E948F14", "41C4F2F37C0B257D1E20FE167F2098DA9D2E0A939B09ED3F63BC4FE010F8365C", "D8CAF4581C9F0000C7568D78FB7D2E595AB36134E2346297D78615942CBBD727", "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349", "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a", "0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f", "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a", "1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb", "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956", "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba", "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538", "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9", "7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca", "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7", "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0", "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073", "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7", "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926", "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3", "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c", "e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea", "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243", "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf", "e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49", "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b", "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c", "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152", "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d") or MD5 in~ ("30015DD1E2CF4DBD49FFF9DDEF2AD4622DA2E60E5C0B6228595325532E948F14", "41C4F2F37C0B257D1E20FE167F2098DA9D2E0A939B09ED3F63BC4FE010F8365C", "D8CAF4581C9F0000C7568D78FB7D2E595AB36134E2346297D78615942CBBD727", "0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349", "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a", "0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f", "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a", "1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb", "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956", "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba", "6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538", "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9", "7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca", "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7", "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0", "887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073", "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7", "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926", "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3", "d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c", "e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea", "e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243", "e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf", "e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49", "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b", "ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c", "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152", "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
