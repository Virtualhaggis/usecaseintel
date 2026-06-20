# [CRIT] Gentlemen ransomware uses multiple EDR killers to disable defenses

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/gentlemen-ransomware-uses-multiple-edr-killers-to-disable-defenses/

## Threat Profile

Gentlemen ransomware uses multiple EDR killers to disable defenses 
By Bill Toulas 
June 18, 2026
06:31 PM
0 
The Gentlemen ransomware-as-a-service (RaaS) is actively developing and maintaining a suite of endpoint detection and response (EDR) killers to help affiliates evade detection in attacks.
The gang employs a collection of EDR-killing tools, most notably a utility that researchers dubbed GentleKiller. The tool has at least eight variants and impersonates various legitimate security product…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-42045`
- **CVE:** `CVE-2025-26125`
- **SHA1:** `8AE6BD18B129061F63642531F1B684CF0383C75D`
- **SHA1:** `BA914FE77B177B45799403B16DD14765C510A074`
- **SHA1:** `D605994FC72A2BB59B5CFB1624A1B9170ECA73A2`
- **SHA1:** `B0B912A3FD1C05D72080848EC4C92880004021A1`
- **SHA1:** `5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3`
- **SHA1:** `7556AE58C215B8245A43F764F0676C7A8F0FDD1A`
- **SHA1:** `331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6`
- **SHA1:** `F11AEBCCB9A86A7E2E653F90BAEC697F233C255F`
- **SHA1:** `EF9CD06683159397F099CAA244E94E6EAAD96EBA`
- **SHA1:** `711EF221526997039E804A18DB9647C91680BBE2`
- **SHA1:** `68FEC379F2AE76C3D2CE913F7BE650CEA1D06990`
- **SHA1:** `A11EE9CDC59E5CAA59AEFD27B30D104F3AD68E62`
- **SHA1:** `96F0DBF52AED0AFD43E44500116B04B674F7358E`
- **SHA1:** `2F86898528C6CAB3540C486A9BFAA0C029B73950`
- **SHA1:** `9AD51AD97C01E97AB59214116740785E0F6320A8`
- **SHA1:** `A19117175DBC9BA4D23B5DCE8415E299A2E32192`
- **SHA1:** `12500F6C87CE62712A0ED6652C57468D15C14223`
- **SHA1:** `D29670E684E40DDC89B47010C37CBC96737035B6`
- **SHA1:** `56BEE9DF5833A637F5C54D5911DF98B0812FE643`
- **SHA1:** `CF4D74DF17A91B4A36A2911B22AFEC5D8FA93A01`
- **SHA1:** `EC296F9501AD71E430810CB5CDC38D954D4BA536`
- **SHA1:** `7131B377E96016DC1911020C9F95B1B4D042D7B4`
- **SHA1:** `82ED942A52CDCF120A8919730E00BA37619661A3`
- **SHA1:** `F0537CBB773AE12100B36731E7C39F5A9D852B14`
- **SHA1:** `1FA071303FB846308571E64727501FB98B1C2BE6`
- **SHA1:** `A5CF917EC4A7DFBDFA43621398604805D860C718`
- **SHA1:** `D4B19141102015D436321E6F26976E98183CFD27`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information

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
  - CVE(s): `CVE-2022-42045`, `CVE-2025-26125`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8AE6BD18B129061F63642531F1B684CF0383C75D`, `BA914FE77B177B45799403B16DD14765C510A074`, `D605994FC72A2BB59B5CFB1624A1B9170ECA73A2`, `B0B912A3FD1C05D72080848EC4C92880004021A1`, `5AA3124E5C4921E5EDFC60133B5D71DA21B07DA3`, `7556AE58C215B8245A43F764F0676C7A8F0FDD1A`, `331879F5EEC8892BBD896F90BDBB1BAD0BF63BD6`, `F11AEBCCB9A86A7E2E653F90BAEC697F233C255F` _(+19 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
