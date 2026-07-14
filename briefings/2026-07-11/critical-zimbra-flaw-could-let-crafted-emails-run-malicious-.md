# [CRIT] Critical Zimbra Flaw Could Let Crafted Emails Run Malicious Code in User Sessions

**Source:** The Hacker News
**Published:** 2026-07-11
**Article:** https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html

## Threat Profile

Critical Zimbra Flaw Could Let Crafted Emails Run Malicious Code in User Sessions 
 Ravie Lakshmanan  Jul 11, 2026 Vulnerability / Email Security 
Zimbra is urging customers to apply updates to address a critical security vulnerability impacting the Classic Web Client that could result in arbitrary code execution.
The vulnerability has been described as a case of stored cross-site scripting (XSS) that could allow specially crafted emails to execute malicious scripts in a user's session. It has…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-27915`
- **CVE:** `CVE-2023-37580`
- **CVE:** `CVE-2024-27443`
- **Domain (defanged):** `attacker.example`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1203** — Exploitation for Client Execution
- **T1566.001** — Spearphishing Attachment
- **T1114.003** — Email Forwarding Rule
- **T1564.008** — Email Hiding Rules
- **T1114.002** — Remote Email Collection
- **T1119** — Automated Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable Zimbra Classic Web Client exposure (ZCS < 10.1.19)

`UC_59_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.signature="*zimbra*" OR Vulnerabilities.category="*zimbra*" OR Vulnerabilities.signature="*Classic Web Client*") by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor has "zimbra" or SoftwareName has "zimbra"
| extend v = split(SoftwareVersion, ".")
| extend vMajor = toint(v[0]), vMinor = toint(v[1]), vPatch = toint(extract(@"^(\d+)", 1, tostring(v[2])))
| where isnotempty(vMajor)
| where vMajor < 10 or (vMajor == 10 and vMinor < 1) or (vMajor == 10 and vMinor == 1 and vPatch < 19)
| project DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus
| sort by SoftwareVersion asc
```

### Zimbra crafted-email XSS payload: HTML event-handler / <details ontoggle> in mail or SOAP traffic

`UC_59_8` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where (Web.dest="*zimbra*" OR Web.url="*/service/soap*" OR Web.url="*/h/*") AND (Web.url="*ontoggle*" OR Web.url="*onerror%3D*" OR Web.url="*onload%3D*" OR Web.url="*%3Cdetails*" OR Web.url="*%3Cscript*" OR Web.url="*javascript%3A*") by Web.src, Web.dest, Web.http_method, Web.url | `drop_dm_object_name(Web)` | sort - count
```

### Zimbra malicious sieve filter creating external mail-forwarding rule (post-XSS takeover)

`UC_59_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype="zimbra:mailbox" OR sourcetype="zimbra*" OR source="*mailbox.log*" OR source="*audit.log*") ("ModifyFilterRulesRequest" OR "CreateFilterRulesRequest" OR "actionRedirect" OR "zimbraMailSieveScript") ("Correo" OR "proton.me" OR "protonmail.com" OR "spam_to_junk" OR "actionRedirect") | rex field=_raw "name=(?<zimbra_account>[^;]+);" | rex field=_raw "oip=(?<client_ip>[0-9\.]+)" | table _time host zimbra_account client_ip _raw | sort - _time
```

### Zimbra webmail session mass mailbox harvest via SOAP (bulk Search/GetMsg)

`UC_59_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype="zimbra:mailbox" OR source="*mailbox.log*") ("SearchRequest" OR "GetMsgRequest" OR "GetContactsRequest" OR "SearchConvRequest") | rex field=_raw "name=(?<zimbra_account>[^;]+);" | rex field=_raw "oip=(?<client_ip>[0-9\.]+)" | bin _time span=5m | stats count as mailbox_reads dc(_raw) as distinct_ops values(client_ip) as client_ips by zimbra_account _time | where mailbox_reads>150 | sort - mailbox_reads
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe")
| where RemoteUrl has_any ("proton.me","protonmail.com","mail.proton.me")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-27915`, `CVE-2023-37580`, `CVE-2024-27443`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `attacker.example`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
