# [HIGH] Supply Chain Security Alert: num2words PyPI Package Shows Signs of Compromise

**Source:** StepSecurity
**Published:** 2025-08-09
**Article:** https://www.stepsecurity.io/blog/supply-chain-security-alert-num2words-pypi-package-shows-signs-of-compromise

## Threat Profile

Back to Blog Threat Intel Supply Chain Security Alert: num2words PyPI Package Shows Signs of Compromise Popular Python Package num2words v0.5.15 Published Without Repository Tag, Linked to Known Threat Actor Ashish Kurmi View LinkedIn July 28, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Key Takeaways The Python package num2words version 0.5.15 was published to PyPI without a corresponding tag in the official GitHub reposit…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1555** — Credentials from Password Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PyPI install footprint of num2words v0.5.15/0.5.16 (Scavenger supply-chain compromise)

`UC_672_1` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe","pip","pip3","python","python3") (Processes.process="*num2words==0.5.15*" OR Processes.process="*num2words==0.5.16*" OR Processes.process="*num2words-0.5.15*" OR Processes.process="*num2words-0.5.16*") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*site-packages*num2words-0.5.15*" OR Filesystem.file_path="*site-packages*num2words-0.5.16*" OR (Filesystem.file_path="*site-packages*num2words*" Filesystem.file_name="_build.py")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe")
    or InitiatingProcessFileName in~ ("pip.exe","pip3.exe","python.exe","python3.exe","uv.exe","poetry.exe")
| where ProcessCommandLine has_any ("num2words==0.5.15","num2words==0.5.16","num2words-0.5.15","num2words-0.5.16")
    or InitiatingProcessCommandLine has_any ("num2words==0.5.15","num2words==0.5.16")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has "site-packages" and FolderPath has_any (@"num2words-0.5.15", @"num2words-0.5.16"))
    or (FolderPath has @"\num2words\" and FileName =~ "_build.py" and InitiatingProcessFileName in~ ("pip.exe","python.exe","python3.exe","uv.exe"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] Scavenger C2 callback: ifyouseethisyouareultragay[.]com / pokerainteasy[.]su

`UC_672_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query="ifyouseethisyouareultragay.com" OR DNS.query="*.ifyouseethisyouareultragay.com" OR DNS.query="pokerainteasy.su" OR DNS.query="*.pokerainteasy.su") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Web where (Web.url="*ifyouseethisyouareultragay.com*" OR Web.url="*pokerainteasy.su*" OR Web.dest="ifyouseethisyouareultragay.com" OR Web.dest="pokerainteasy.su") by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("ifyouseethisyouareultragay.com","pokerainteasy.su")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
| where QueryName has_any ("ifyouseethisyouareultragay.com","pokerainteasy.su")
| project Timestamp, DeviceName, QueryName, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] Scavenger loader/stealer SHA256 execution or drop on endpoint

`UC_672_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("be917cb379b9622f56a4d5ec93bf00c20cb76c6646e5919690d0f7c09c956de2","c2a7ee6ab9344e1bb13c61dc689d4a946678e0505367cd55c9b43ddee3d461e2","439da8bb9c541d26b0f534b17d75790e252e4d9058561e8907f8690e21cd0616","c36ebf96573afcb36bb31590d56e8af49502fb159e00fd4a59336f8a450bec8b") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_hash IN ("be917cb379b9622f56a4d5ec93bf00c20cb76c6646e5919690d0f7c09c956de2","c2a7ee6ab9344e1bb13c61dc689d4a946678e0505367cd55c9b43ddee3d461e2","439da8bb9c541d26b0f534b17d75790e252e4d9058561e8907f8690e21cd0616","c36ebf96573afcb36bb31590d56e8af49502fb159e00fd4a59336f8a450bec8b") by Processes.dest Processes.user Processes.process_name Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let scavenger_hashes = dynamic([
  "be917cb379b9622f56a4d5ec93bf00c20cb76c6646e5919690d0f7c09c956de2",
  "c2a7ee6ab9344e1bb13c61dc689d4a946678e0505367cd55c9b43ddee3d461e2",
  "439da8bb9c541d26b0f534b17d75790e252e4d9058561e8907f8690e21cd0616",
  "c36ebf96573afcb36bb31590d56e8af49502fb159e00fd4a59336f8a450bec8b"
]);
union
(DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (scavenger_hashes)
| project Timestamp, Source="DeviceFileEvents", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (scavenger_hashes)
| project Timestamp, Source="DeviceImageLoadEvents", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=InitiatingProcessAccountName),
(DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (scavenger_hashes) or InitiatingProcessSHA256 in~ (scavenger_hashes)
| project Timestamp, Source="DeviceProcessEvents", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName)
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


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
