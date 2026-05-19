# [HIGH] PromptSpy ushers in the era of Android threats using GenAI

**Source:** ESET WeLiveSecurity
**Published:** 2026-02-19
**Article:** https://www.welivesecurity.com/en/eset-research/promptspy-ushers-in-era-android-threats-using-genai/

## Threat Profile

ESET researchers uncovered the first known case of Android malware abusing generative AI for context-aware user interface manipulation. While machine learning has been used to similar ends already – just recently, researchers at Dr.WEB found Android.Phantom , which uses TensorFlow machine learning models to analyze advertisement screenshots and automatically click on detected elements for large scale ad fraud – this is the first time we have seen generative AI deployed in this manner. Because th…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1189** — Drive-by Compromise
- **T1583.001** — Acquire Infrastructure: Domains
- **T1204.002** — User Execution: Malicious File
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PromptSpy/VNCSpy Android malware C2 callback to hard-coded VNC server (54.67.2.84 / 52.222.205.45)

`UC_398_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as apps values(All_Traffic.transport) as transports from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest in ("54.67.2.84","52.222.205.45") by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let promptspy_c2 = dynamic(["54.67.2.84","52.222.205.45"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (promptspy_c2)
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteIP, RemotePort, Protocol, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] PromptSpy MorganArg distribution / phishing domain access (mgardownload.com, m-mgarg.com)

`UC_398_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.answer) as resolved_ips values(DNS.record_type) as record_types from datamodel=Network_Resolution.DNS where (DNS.query="mgardownload.com" OR DNS.query="*.mgardownload.com" OR DNS.query="m-mgarg.com" OR DNS.query="*.m-mgarg.com") by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| append 
    [| tstats summariesonly=true count from datamodel=Web.Web where (Web.url="*mgardownload.com*" OR Web.url="*m-mgarg.com*" OR Web.site="mgardownload.com" OR Web.site="m-mgarg.com") by Web.src Web.user Web.site Web.url Web.http_user_agent
     | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
let promptspy_domains = dynamic(["mgardownload.com","m-mgarg.com"]);
union isfuzzy=true
  ( DeviceEvents
      | where Timestamp > ago(30d)
      | where ActionType == "DnsQueryResponse"
      | extend Query = tostring(parse_json(AdditionalFields).QueryName)
      | where Query has_any (promptspy_domains)
      | project Timestamp, DeviceName, DeviceId, Query, InitiatingProcessFileName,
                InitiatingProcessCommandLine, InitiatingProcessAccountName, Source="DnsQueryResponse" ),
  ( DeviceNetworkEvents
      | where Timestamp > ago(30d)
      | where RemoteUrl has_any (promptspy_domains)
      | project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP, RemotePort,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                InitiatingProcessAccountUpn, Source="DeviceNetworkEvents" ),
  ( UrlClickEvents
      | where Timestamp > ago(30d)
      | where Url has_any (promptspy_domains)
      | project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress,
                NetworkMessageId, Workload, Source="UrlClickEvents" )
| order by Timestamp desc
```

### [LLM] PromptSpy / VNCSpy APK SHA-1 IOC match on managed-endpoint file events

`UC_398_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.user) as users from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("6BBC9AB132BA066F63676E05DA13D108598BC29B","375D7423E63C8F5F2CC814E8CFE697BA25168AFA","3978AC5CD14E357320E127D6C87F10CB70A1DCC2","E60D12017D2DA579DF87368F5596A0244621AE86","9B1723284E311794987997CB7E8814EB6014713F","076801BD9C6EB78FC0331A4C7A22C73199CC3824","8364730E9BB2CF3A4B016DE1B34F38341C0EE2FA","F8F4C5BC498BCCE907DC975DD88BE8D594629909","C14E9B062ED28115EDE096788F62B47A6ED841AC") by Filesystem.dest Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let promptspy_sha1 = dynamic([
  "6BBC9AB132BA066F63676E05DA13D108598BC29B",
  "375D7423E63C8F5F2CC814E8CFE697BA25168AFA",
  "3978AC5CD14E357320E127D6C87F10CB70A1DCC2",
  "E60D12017D2DA579DF87368F5596A0244621AE86",
  "9B1723284E311794987997CB7E8814EB6014713F",
  "076801BD9C6EB78FC0331A4C7A22C73199CC3824",
  "8364730E9BB2CF3A4B016DE1B34F38341C0EE2FA",
  "F8F4C5BC498BCCE907DC975DD88BE8D594629909",
  "C14E9B062ED28115EDE096788F62B47A6ED841AC"]);
let promptspy_filenames = dynamic([
  "net.ustexas.myavlive.apk","nlll4.un7o6.q38l5.apk","ppyzz.dpk0p.ln441.apk",
  "mgappc-1.apk","mgappm-1.apk","mgappn-0.apk","mgappn-1.apk",
  "app-release.apk","mgapp.apk"]);
union isfuzzy=true
  ( DeviceFileEvents
      | where Timestamp > ago(30d)
      | where SHA1 in (promptspy_sha1) or FileName in~ (promptspy_filenames)
      | project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath,
                SHA1, SHA256, FileOriginUrl, FileOriginReferrerUrl,
                InitiatingProcessFileName, InitiatingProcessFolderPath,
                InitiatingProcessAccountName, InitiatingProcessAccountUpn, Source="DeviceFileEvents" ),
  ( EmailAttachmentInfo
      | where Timestamp > ago(30d)
      | where FileName in~ (promptspy_filenames) or FileType =~ "APK"
      | join kind=leftouter (EmailEvents | project NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction) on NetworkMessageId
      | project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
                Subject, FileName, FileType, SHA256, MalwareFilterVerdict, DeliveryAction, Source="EmailAttachmentInfo" )
| order by Timestamp desc
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
