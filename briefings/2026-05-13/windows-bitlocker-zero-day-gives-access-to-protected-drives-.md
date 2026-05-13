# [HIGH] Windows BitLocker zero-day gives access to protected drives, PoC released

**Source:** BleepingComputer
**Published:** 2026-05-13
**Article:** https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/

## Threat Profile

Windows BitLocker zero-day gives access to protected drives, PoC released 
By Bill Toulas 
May 13, 2026
12:37 PM
0 


A cybersecurity researcher has published proof-of-concept (PoC) exploits for two unpatched Microsoft Windows vulnerabilities named YellowKey and GreenPlasma, which are a BitLocker bypass and a privilege-escalation flaw.

Known as Chaotic Eclipse or Nightmare Eclipse, the researcher describes the BitLocker bypass issue as functioning like a backdoor because the vulnerable compo…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33825`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1006** — Direct Volume Access
- **T1078.003** — Valid Accounts: Local Accounts
- **T1601.001** — Modify System Image: Patch System Image
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] YellowKey BitLocker bypass: FsTx payload drop to removable / EFI volume

`UC_0_2` · phase: **weapon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user values(Filesystem.dest) as dest from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*\\System Volume Information\\FsTx\\*" OR Filesystem.file_path="*\\system volume information\\fstx\\*" OR Filesystem.file_name="95F62703B343F111A92A005056975458*") NOT (Filesystem.user IN ("*SYSTEM","*LOCAL SERVICE","*NETWORK SERVICE")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// YellowKey staging — FsTx payload written to System Volume Information on any attached/removable volume
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\System Volume Information\FsTx"
   or FileName has "95F62703B343F111A92A005056975458"   // public-PoC GUID folder
| where InitiatingProcessAccountName !endswith "$"        // exclude machine accounts
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| where InitiatingProcessFileName !in~ ("system","vssvc.exe","searchindexer.exe","svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          DroppedFile = FileName, DropPath = FolderPath,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          WriterPath = InitiatingProcessFolderPath,
          SHA256
| order by Timestamp desc
```

### [LLM] WinRE winpeshl.ini deletion or tampering (YellowKey post-exploit marker)

`UC_0_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.action) as action values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_name="winpeshl.ini" OR Filesystem.file_path="*\\Windows\\System32\\winpeshl.ini") Filesystem.action IN ("deleted","modified","renamed") NOT (Filesystem.process_name IN ("TrustedInstaller.exe","msiexec.exe","DISM.exe","dism.exe")) by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// YellowKey post-exploit — winpeshl.ini removed or rewritten outside of legit servicing
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "winpeshl.ini"
   or FolderPath endswith @"\Windows\System32\winpeshl.ini"
   or FolderPath endswith @"\Recovery\WindowsRE\winpeshl.ini"
| where ActionType in ("FileDeleted","FileModified","FileRenamed","FileCreated")
| where InitiatingProcessFileName !in~ ("trustedinstaller.exe","tiworker.exe","msiexec.exe","dism.exe","reagentc.exe","setuphost.exe")
| project Timestamp, DeviceName, ActionType,
          PathTouched = FolderPath, FileName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          WriterAccount = InitiatingProcessAccountName,
          IntegrityLevel = InitiatingProcessIntegrityLevel,
          SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Windows BitLocker zero-day gives access to protected drives, PoC released

`UC_0_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Windows BitLocker zero-day gives access to protected drives, PoC released ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_path="*X:\Windows\System32\winpeshl.ini*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*X:\Windows\System32\winpeshl.ini*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Windows BitLocker zero-day gives access to protected drives, PoC released
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FolderPath has_any ("X:\Windows\System32\winpeshl.ini"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("X:\Windows\System32\winpeshl.ini"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33825`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
