# [CRIT] The who, where, and how of APT attacks in Q2 2025–Q3 2025

**Source:** ESET WeLiveSecurity
**Published:** 2025-11-07
**Article:** https://www.welivesecurity.com/en/videos/who-where-how-apt-attacks-q2-2025-q3-2025/

## Threat Profile

The who, where, and how of APT attacks in Q2 2025–Q3 2025 
Video
The who, where, and how of APT attacks in Q2 2025–Q3 2025 ESET Chief Security Evangelist Tony Anscombe highlights some of the key findings from the latest issue of the ESET APT Activity Report
Editor 
07 Nov 2025 
Yesterday, the ESET research team released the latest issue of its APT Activity Report  that summarizes and contextualizes the cyber-operations of some of the world's most notorious state-aligned hacking groups from April…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-8088`
- **Domain (defanged):** `esetsmart.com`
- **Domain (defanged):** `esetscanner.com`
- **Domain (defanged):** `esetremover.com`
- **SHA256:** `e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389`
- **SHA256:** `bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1203** — Exploitation for Client Execution
- **T1059.001** — PowerShell
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1133** — External Remote Services
- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
- **T1090.003** — Proxy: Multi-hop Proxy (Tor)
- **T1204.002** — User Execution: Malicious File
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] WinRAR CVE-2025-8088 ADS path-traversal drop into Windows Startup folder

`UC_582_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path values(Filesystem.file_name) as file_name values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("winrar.exe","rar.exe","unrar.exe","wzip.exe","7zg.exe","7zfm.exe") AND Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*" AND (Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.exe" OR Filesystem.file_name="*.dll" OR Filesystem.file_name="*.cmd" OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.js" OR Filesystem.file_name="*.scr") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has @"\Start Menu\Programs\Startup\" or FolderPath has @"\Start Menu\Programs\StartUp\"
| where InitiatingProcessFileName in~ ("winrar.exe","rar.exe","unrar.exe","wzip.exe","7zg.exe","7zfm.exe")
| where FileName endswith ".lnk" or FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".cmd" or FileName endswith ".bat" or FileName endswith ".vbs" or FileName endswith ".js" or FileName endswith ".scr"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] Egress to InedibleOchotense ESET-impersonating phishing domains (esetsmart/esetscanner/esetremover)

`UC_582_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as resolved_ip values(DNS.query) as query from datamodel=Network_Resolution where DNS.query IN ("esetsmart.com","esetscanner.com","esetremover.com","*.esetsmart.com","*.esetscanner.com","*.esetremover.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=true count from datamodel=Web where Web.url IN ("*esetsmart.com*","*esetscanner.com*","*esetremover.com*") by Web.src Web.url Web.http_user_agent | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
let _bad_domains = dynamic(["esetsmart.com","esetscanner.com","esetremover.com"]);
let _network = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (_bad_domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceSource="NetworkConnection";
let _dns = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where QueryName has_any (_bad_domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteUrl=QueryName, RemoteIP="", RemotePort=int(null), InitiatingProcessFileName, InitiatingProcessCommandLine, EvidenceSource="DnsQuery";
union _network, _dns
| order by Timestamp desc
```

### [LLM] Kalambur backdoor post-install: RDP enablement + OpenSSH install from non-admin context

`UC_582_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_key_name) as registry_key values(Registry.registry_value_name) as value_name values(Registry.registry_value_data) as value_data values(Registry.process_name) as parent_proc values(Registry.user) as user from datamodel=Endpoint.Registry where (Registry.registry_key_name="*\\Terminal Server" AND Registry.registry_value_name="fDenyTSConnections" AND Registry.registry_value_data="0x00000000") OR (Registry.registry_key_name="*\\WindowsFirewall\\FirewallRules\\*" AND Registry.registry_value_data="*LPort=3389*" AND Registry.registry_value_data="*Action=Allow*") by Registry.dest Registry.registry_key_name Registry.registry_value_name | `drop_dm_object_name(Registry)` | search NOT parent_proc IN ("ServerManager.exe","SystemSettings.exe","mmc.exe","gpscript.exe","TiWorker.exe","TrustedInstaller.exe","svchost.exe","MsMpEng.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _rdp_enable = DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where (RegistryKey has @"\Terminal Server" and RegistryValueName =~ "fDenyTSConnections" and RegistryValueData == "0")
        or (RegistryKey has @"\WindowsFirewall\FirewallRules" and RegistryValueData has "LPort=3389" and RegistryValueData has "Action=Allow")
    | where InitiatingProcessFileName !in~ ("ServerManager.exe","SystemSettings.exe","mmc.exe","gpscript.exe","TiWorker.exe","TrustedInstaller.exe","MsMpEng.exe","svchost.exe","GPUpdate.exe")
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, DeviceName, Signal="RDP_Enable", RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath;
let _openssh_install = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (FileName =~ "powershell.exe" and ProcessCommandLine has_all ("Add-WindowsCapability","OpenSSH.Server"))
        or (FileName =~ "dism.exe" and ProcessCommandLine has "OpenSSH.Server")
        or (FileName =~ "sc.exe" and ProcessCommandLine has_all ("create","sshd"))
        or (FileName =~ "sshd.exe" and InitiatingProcessFileName !=~ "services.exe")
    | where InitiatingProcessAccountName !endswith "$"
    | project Timestamp, DeviceName, Signal="OpenSSH_Install", RegistryKey="", RegistryValueName="", RegistryValueData=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath;
union _rdp_enable, _openssh_install
| order by Timestamp desc
```

### [LLM] Known SHA256 IOCs from ESET APT Q2-Q3 2025 report (Kalambur/RomCom delivery)

`UC_582_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as process_name values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047") by Processes.dest Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389","bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047") by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let _bad_sha256 = dynamic([
    "e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389",
    "bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047"
]);
let _proc = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (_bad_sha256) or InitiatingProcessSHA256 in~ (_bad_sha256)
    | project Timestamp, DeviceName, AccountName, Source="Process", FileName, FolderPath, ProcessCommandLine, SHA256=coalesce(SHA256, InitiatingProcessSHA256);
let _file = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (_bad_sha256)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="FileWrite", FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256;
let _load = DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (_bad_sha256)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="ImageLoad", FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256;
let _alert = AlertEvidence
    | where Timestamp > ago(30d)
    | where SHA256 in~ (_bad_sha256)
    | project Timestamp, DeviceName, AccountName, Source="AlertEvidence", FileName, FolderPath, ProcessCommandLine, SHA256;
union _proc, _file, _load, _alert
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-8088`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `esetsmart.com`, `esetscanner.com`, `esetremover.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389`, `bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
