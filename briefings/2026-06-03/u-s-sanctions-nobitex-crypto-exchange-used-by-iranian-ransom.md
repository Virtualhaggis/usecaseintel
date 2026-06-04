# [HIGH] U.S. sanctions Nobitex crypto exchange used by Iranian ransomware actors

**Source:** BleepingComputer
**Published:** 2026-06-03
**Article:** https://www.bleepingcomputer.com/news/security/the-us-sanctions-nobitex-crypto-exchange-used-by-ransomware/

## Threat Profile

The U.S. sanctions Nobitex crypto exchange used by ransomware 
By Bill Toulas 
June 3, 2026
04:31 PM
0 
The U.S. Treasury's Office of Foreign Assets Control (OFAC) has announced sanctions against Nobitex, Iran's largest cryptocurrency exchange, for facilitating payments related to terrorist activities.
Nobitex is believed to have helped evade economic sanctions and also facilitated transactions linked to the Islamic Revolutionary Guard Corps (IRGC).
Among the transactions, the U.S. authorities f…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `Nobitex.ir`
- **Domain (defanged):** `Wallex.ir`
- **Domain (defanged):** `Bitcoin.ir`
- **Domain (defanged):** `Rumzinex.com`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1657** — Financial Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Network egress to OFAC-sanctioned Iranian crypto exchanges (Nobitex, Wallex, Bitpin, Ramzinex)

`UC_43_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url IN ("*nobitex.ir*","*wallex.ir*","*bitpin.ir*","*ramzinex.com*","*rumzinex.com*") OR Web.dest IN ("*nobitex.ir","*wallex.ir","*bitpin.ir","*ramzinex.com","*rumzinex.com")) by Web.src Web.user Web.dest Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("*nobitex.ir","*wallex.ir","*bitpin.ir","*ramzinex.com","*rumzinex.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | rename query as dest ] | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let SanctionedDomains = dynamic(["nobitex.ir","wallex.ir","bitpin.ir","ramzinex.com","rumzinex.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (SanctionedDomains)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `Nobitex.ir`, `Wallex.ir`, `Bitcoin.ir`, `Rumzinex.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
