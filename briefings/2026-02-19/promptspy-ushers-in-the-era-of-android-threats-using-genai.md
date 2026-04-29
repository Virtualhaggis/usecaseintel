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
- **T1437.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1521.001** — Encrypted Channel: Symmetric Cryptography
- **T1646** — Exfiltration Over C2 Channel
- **T1660** — Phishing (Mobile)
- **T1456** — Drive-By Compromise (Mobile)
- **T1404** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### [LLM] PromptSpy Android RAT C2 / distribution-site network callouts

`UC_192_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution where DNS.query IN ("mgardownload.com","*.mgardownload.com","m-mgarg.com","*.m-mgarg.com") by DNS.src DNS.query 
| append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic where All_Traffic.dest_ip IN ("54.67.2.84","52.222.205.45") by All_Traffic.src All_Traffic.dest_ip] 
| append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.url) as url from datamodel=Web where Web.url IN ("*mgardownload.com*","*m-mgarg.com*") OR Web.dest IN ("54.67.2.84","52.222.205.45") by Web.src Web.dest] 
| convert ctime(firstTime) ctime(lastTime) 
| `drop_dm_object_name("DNS")` `drop_dm_object_name("All_Traffic")` `drop_dm_object_name("Web")`
```

**Defender KQL:**
```kql
let promptspy_ips = dynamic(["54.67.2.84","52.222.205.45"]);
let promptspy_doms = dynamic(["mgardownload.com","m-mgarg.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (promptspy_ips)
   or RemoteUrl has_any (promptspy_doms)
   or tostring(parse_json(AdditionalFields).host) has_any (promptspy_doms)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| union (
    DeviceEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (promptspy_doms) or RemoteIP in (promptspy_ips)
    | project Timestamp, DeviceName, DeviceId, RemoteIP, RemoteUrl, ActionType
)
| sort by Timestamp desc
```

### [LLM] PromptSpy / VNCSpy APK file landing (hash + Chase-Argentina lure)

`UC_192_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as host values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.apk" OR Filesystem.file_path="*MorganArg*" OR Filesystem.file_path="*mgar*") AND (Filesystem.file_hash IN ("6BBC9AB132BA066F63676E05DA13D108598BC29B","375D7423E63C8F5F2CC814E8CFE697BA25168AFA","3978AC5CD14E357320E127D6C87F10CB70A1DCC2","E60D12017D2DA579DF87368F5596A0244621AE86","9B1723284E311794987997CB7E8814EB6014713F","076801BD9C6EB78FC0331A4C7A22C73199CC3824","8364730E9BB2CF3A4B016DE1B34F38341C0EE2FA","F8F4C5BC498BCCE907DC975DD88BE8D594629909","C14E9B062ED28115EDE096788F62B47A6ED841AC")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash 
| convert ctime(firstTime) ctime(lastTime) 
| `drop_dm_object_name("Filesystem")`
```

**Defender KQL:**
```kql
let promptspy_sha1 = dynamic(["6BBC9AB132BA066F63676E05DA13D108598BC29B","375D7423E63C8F5F2CC814E8CFE697BA25168AFA","3978AC5CD14E357320E127D6C87F10CB70A1DCC2","E60D12017D2DA579DF87368F5596A0244621AE86","9B1723284E311794987997CB7E8814EB6014713F","076801BD9C6EB78FC0331A4C7A22C73199CC3824","8364730E9BB2CF3A4B016DE1B34F38341C0EE2FA","C14E9B062ED28115EDE096788F62B47A6ED841AC"]);
let promptspy_sha256 = dynamic(["F8F4C5BC498BCCE907DC975DD88BE8D594629909"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA1 in~ (promptspy_sha1)
   or SHA256 in~ (promptspy_sha256)
   or (FileName endswith ".apk" and (FileName has_any ("MorganArg","mgar","Chase") or FolderPath has_any ("MorganArg","mgar")))
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, SHA1, SHA256, RequestSourceIP, RequestAccountName
| union (
    EmailAttachmentInfo
    | where Timestamp > ago(30d)
    | where SHA256 in~ (promptspy_sha256) or FileName endswith ".apk" and FileName has_any ("MorganArg","mgar")
    | project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, SHA256
)
| sort by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
