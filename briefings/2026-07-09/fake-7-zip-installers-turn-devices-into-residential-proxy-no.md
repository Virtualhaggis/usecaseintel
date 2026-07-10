# [HIGH] Fake 7-Zip Installers Turn Devices Into Residential Proxy Nodes

**Source:** The Hacker News
**Published:** 2026-07-09
**Article:** https://thehackernews.com/2026/07/fake-7-zip-installers-turn-devices-into.html

## Threat Profile

Fake 7-Zip Installers Turn Devices Into Residential Proxy Nodes 
 Ravie Lakshmanan  Jul 09, 2026 Malware / Threat Intelligence 
Cybersecurity researchers have disclosed details of a new threat actor dubbed Lurking Lizard that has been operating an end-to-end malicious residential proxy business using an infrastructure comprising more than 230 lookalike domains.
The activity dates back to at least August 2022, according to DNS threat intelligence firm Infoblox. Once such campaign, observed earl…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `7zip.com`
- **Domain (defanged):** `whtatsapp.net`
- **Domain (defanged):** `wirevpn.app`
- **Domain (defanged):** `wirevpn.cc`
- **Domain (defanged):** `wirevpn.io`
- **Domain (defanged):** `betflixfree.net`
- **Domain (defanged):** `isharkvpn.com`
- **Domain (defanged):** `snaptik.io`
- **Domain (defanged):** `bintangwarisanhotel.com`
- **Domain (defanged):** `proxyreviews.org`
- **Domain (defanged):** `norton-com-nu16.com`
- **Domain (defanged):** `breakoursilence.com`
- **Domain (defanged):** `visitbenin.org`
- **Domain (defanged):** `smartproxy.org`
- **Domain (defanged):** `ipidea.org`
- **Domain (defanged):** `911proxy.com`
- **Domain (defanged):** `iplogger.com/mnWD`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1102** — Web Service
- **T1090** — Proxy
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Lurking Lizard proxyware lookalike distribution/proxy-brand domain resolution

`UC_58_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("7zip.com","*.7zip.com","whtatsapp.net","*.whtatsapp.net","wirevpn.app","wirevpn.cc","wirevpn.io","snaptik.io","isharkvpn.com","betflixfree.net","smartproxy.org","ipidea.org","911proxy.com") by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("7zip.com","whtatsapp.net","wirevpn.app","wirevpn.cc","wirevpn.io","snaptik.io","isharkvpn.com","betflixfree.net","smartproxy.org","ipidea.org","911proxy.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### IPLogger tracking beacon (iplogger.com/mnWD) from non-browser process

`UC_58_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*iplogger.com/mnWD*" OR Web.dest="iplogger.com") by Web.src Web.dest Web.url Web.http_user_agent Web.app
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl contains "iplogger.com"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","safari.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Residential-proxy client check-in to /client_v1/config/http and /client_v1/version/server

`UC_58_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/client_v1/config/http*" OR Web.url="*/client_v1/version/server*") by Web.src Web.dest Web.url Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("/client_v1/config/http","/client_v1/version/server")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Fake installer (7-Zip/WhatsApp/WireVPN) written to disk from Lurking Lizard domain

`UC_58_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.dest IN ("7zip.com","whtatsapp.net","wirevpn.app","wirevpn.cc","wirevpn.io","snaptik.io","isharkvpn.com","betflixfree.net")) AND (Web.url="*.exe" OR Web.url="*.msi") by Web.src Web.dest Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileOriginUrl has_any ("7zip.com","whtatsapp.net","wirevpn.app","wirevpn.cc","wirevpn.io","snaptik.io","isharkvpn.com","betflixfree.net")
| where FileName endswith ".exe" or FileName endswith ".msi"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName
| order by Timestamp desc
```

### Trojanized 7-Zip/WireVPN installer spawning command interpreter or LOLBin

`UC_58_11` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("7z.exe","7zFM.exe","7zG.exe","7zip.exe","7-zip.exe","wirevpn.exe","snaptik.exe","isharkvpn.exe") OR Processes.parent_process="*7-zip*setup*" OR Processes.parent_process="*wirevpn*setup*" OR Processes.parent_process="*snaptik*setup*") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","curl.exe","bitsadmin.exe","certutil.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName has_any ("7z","7zip","7-zip","wirevpn","snaptik","isharkvpn","whatsapp")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","curl.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `7zip.com`, `whtatsapp.net`, `wirevpn.app`, `wirevpn.cc`, `wirevpn.io`, `betflixfree.net`, `isharkvpn.com`, `snaptik.io` _(+9 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
