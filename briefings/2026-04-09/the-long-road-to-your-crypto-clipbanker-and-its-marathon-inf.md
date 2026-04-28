# [HIGH] The long road to your crypto: ClipBanker and its marathon infection chain

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-09
**Article:** https://securelist.com/clipbanker-malware-distributed-via-trojanized-proxifier/119341/

## Threat Profile

Table of Contents
Victims 
Conclusion 
Indicators of compromise 
Authors
Oleg Kupreev 
At the start of the year, a certain Trojan caught our eye due to its incredibly long infection chain. In most cases, it kicks off with a web search for “Proxifier”. Proxifiers are speciaized software designed to tunnel traffic for programs that do not natively support proxy servers. They are a go-to for making sure these apps are functional within secured development environments.
By coincidence, Proxifier is …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `pinhole.rootcode.ru`
- **SHA1:** `d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7`
- **MD5:** `107484d66423cb601f418344cd648f12`
- **MD5:** `34a0f70ab100c47caaba7a5c85448e3d`
- **MD5:** `7528bf597fd7764fcb7ec06512e073e0`
- **MD5:** `8354223cd6198b05904337b5dff7772b`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### Asset exposure — vulnerability matches article CVE(s)

`_uc` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Vulnerabilities
    where Vulnerabilities.signature IN ("-")
    by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in~ ("-")
| join kind=inner DeviceInfo on DeviceId
| project DeviceName, OSPlatform, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
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
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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
        where Web.dest IN ("pinhole.rootcode.ru")
        by Web.src, Web.dest, Web.url, Web.user
     | `drop_dm_object_name(Web)`]
| append
    [| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
        where DNS.query IN ("pinhole.rootcode.ru")
        by DNS.src, DNS.query, DNS.answer
     | `drop_dm_object_name(DNS)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("0.0.0.0") or RemoteUrl has_any ("pinhole.rootcode.ru")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### File hash IOCs — endpoint file/process match

`UC_HASH_IOC` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.file_hash IN ("d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7", "107484d66423cb601f418344cd648f12", "34a0f70ab100c47caaba7a5c85448e3d", "7528bf597fd7764fcb7ec06512e073e0", "8354223cd6198b05904337b5dff7772b")
    by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name, Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Processes
        where Processes.process_hash IN ("d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7", "107484d66423cb601f418344cd648f12", "34a0f70ab100c47caaba7a5c85448e3d", "7528bf597fd7764fcb7ec06512e073e0", "8354223cd6198b05904337b5dff7772b")
        by Processes.dest, Processes.user, Processes.process_name, Processes.process_hash
     | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in~ ("d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7", "107484d66423cb601f418344cd648f12", "34a0f70ab100c47caaba7a5c85448e3d", "7528bf597fd7764fcb7ec06512e073e0", "8354223cd6198b05904337b5dff7772b") or SHA1 in~ ("d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7", "107484d66423cb601f418344cd648f12", "34a0f70ab100c47caaba7a5c85448e3d", "7528bf597fd7764fcb7ec06512e073e0", "8354223cd6198b05904337b5dff7772b") or MD5 in~ ("d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7", "107484d66423cb601f418344cd648f12", "34a0f70ab100c47caaba7a5c85448e3d", "7528bf597fd7764fcb7ec06512e073e0", "8354223cd6198b05904337b5dff7772b")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
