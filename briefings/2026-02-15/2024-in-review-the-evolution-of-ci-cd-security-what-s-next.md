# [HIGH] 2024 in Review: The Evolution of CI/CD Security & What's Next

**Source:** StepSecurity
**Published:** 2026-02-15
**Article:** https://www.stepsecurity.io/blog/2024-in-review-the-evolution-of-ci-cd-security-whats-next

## Threat Profile

Back to Blog Resources 2024 in Review: The Evolution of CI/CD Security & What's Next How StepSecurity achieved 5X ARR growth while securing over 5,000 open-source repositories in 2024 Varun Sharma View LinkedIn December 30, 2024
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction As 2024 comes to a close, we've been reflecting on the state of CI/CD security—an area that continues to face growing challenges and opportunitie…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-3094`
- **SHA256:** `319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae`
- **SHA256:** `605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4`
- **SHA256:** `8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd`
- **SHA256:** `b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963`
- **SHA256:** `cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537`
- **SHA256:** `5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1554** — Compromise Host Software Binary
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1496** — Resource Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CVE-2024-3094 XZ Utils backdoored liblzma SHA256 hash match on Linux endpoints

`UC_414_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.dest) as dest from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae","605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4","8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd","b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963","cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537","5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049") by Filesystem.dest Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let xz_backdoor_sha256 = dynamic(["319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae","605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4","8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd","b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963","cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537","5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049"]);
union isfuzzy=true
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (xz_backdoor_sha256)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, EvtTable="DeviceFileEvents"),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (xz_backdoor_sha256) or InitiatingProcessSHA256 in (xz_backdoor_sha256)
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine, ActionType="ProcessExec", EvtTable="DeviceProcessEvents"),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (xz_backdoor_sha256)
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType="ImageLoad", EvtTable="DeviceImageLoadEvents")
| order by Timestamp desc
```

### [LLM] CVE-2024-3094 vulnerable XZ Utils version inventory (xz 5.6.0 / 5.6.1)

`UC_414_4` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Vulnerabilities.dest) as dest values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2024-3094" OR (Vulnerabilities.signature="xz*" AND (Vulnerabilities.signature="*5.6.0*" OR Vulnerabilities.signature="*5.6.1*")) by Vulnerabilities.dest Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2024-3094"
   or (SoftwareName has_any ("xz","xz-utils","xz-libs","liblzma","liblzma5") and SoftwareVersion has_any ("5.6.0","5.6.1"))
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, OSDistribution, OSVersion, MachineGroup, IsInternetFacing) by DeviceId, DeviceName
  ) on DeviceId
| project Timestamp, DeviceName, OSPlatform, OSDistribution, OSVersion,
          SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel,
          RecommendedSecurityUpdate, MachineGroup, IsInternetFacing
| order by IsInternetFacing desc, DeviceName asc
```

### [LLM] Ultralytics PyPI compromised version (8.3.41 / 42 / 45 / 46) install or import

`UC_414_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("pip","pip.exe","pip3","pip3.exe","python","python.exe","python3","python3.exe","uv","uv.exe","poetry","poetry.exe")) AND (Processes.process="*ultralytics==8.3.41*" OR Processes.process="*ultralytics==8.3.42*" OR Processes.process="*ultralytics==8.3.45*" OR Processes.process="*ultralytics==8.3.46*" OR Processes.process="*ultralytics-8.3.41*" OR Processes.process="*ultralytics-8.3.42*" OR Processes.process="*ultralytics-8.3.45*" OR Processes.process="*ultralytics-8.3.46*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let bad_versions = dynamic(["8.3.41","8.3.42","8.3.45","8.3.46"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("pip","pip.exe","pip3","pip3.exe","uv","uv.exe","poetry","poetry.exe","python","python.exe","python3","python3.exe")
    | where ProcessCommandLine has "ultralytics"
    | where ProcessCommandLine has_any ("8.3.41","8.3.42","8.3.45","8.3.46")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, EvtTable="DeviceProcessEvents"),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has_any (@"/site-packages/ultralytics-",@"\site-packages\ultralytics-",@"/ultralytics-8.3.4",@"\ultralytics-8.3.4")
    | where FolderPath has_any ("ultralytics-8.3.41","ultralytics-8.3.42","ultralytics-8.3.45","ultralytics-8.3.46")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, EvtTable="DeviceFileEvents")
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-3094`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae`, `605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4`, `8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd`, `b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963`, `cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537`, `5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
