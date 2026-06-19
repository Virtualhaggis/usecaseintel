# [HIGH] INC Ransomware Uses Rust-Based Windows and Linux/ESXi Encryptors in New Attacks

**Source:** Cyber Security News
**Published:** 2026-06-19
**Article:** https://cybersecuritynews.com/inc-ransomware-uses-rust-based-windows/

## Threat Profile

INC ransomware has grown from a newcomer threat into one of the most dangerous ransomware operations worldwide. What began as an emerging criminal group in mid-2023 has claimed over 800 victims globally, placing it among the top ransomware groups this year. The group runs under a Ransomware-as-a-Service model, recruiting affiliates and supplying them with ready-built [&#8230;] The post INC Ransomware Uses Rust-Based Windows and Linux/ESXi Encryptors in New Attacks appeared first on Cyber Securit…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-3519`
- **CVE:** `CVE-2023-4966`
- **CVE:** `CVE-2024-4885`
- **IPv4 (defanged):** `45.131.41.207`
- **IPv4 (defanged):** `185.68.93.122`
- **IPv4 (defanged):** `185.68.93.233`
- **IPv4 (defanged):** `31.41.44.202`
- **Domain (defanged):** `incapt.su`
- **Domain (defanged):** `inccdn1.lol`
- **Domain (defanged):** `inccdn2.lol`
- **Domain (defanged):** `inccdn3new.lol`
- **Domain (defanged):** `lynxback.pro`
- **Domain (defanged):** `incback.su`
- **Domain (defanged):** `incblog.su`
- **Domain (defanged):** `lynxstorage1.net`
- **Domain (defanged):** `lynxblog.net`
- **Domain (defanged):** `incapt.blog`
- **Domain (defanged):** `incadmin.su`
- **Domain (defanged):** `lynxchat.net`
- **Domain (defanged):** `lynxpanel.net`
- **Domain (defanged):** `incblog7vmuq7rktic73r4ha4j757m3ptym37tyvifzp2roedyyzzxid.onion`
- **Domain (defanged):** `incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion`
- **Domain (defanged):** `lynxbllrfr5262yvbgtqoyq76s7mpztcqkv6tjjxgpilpma7nyoeohyd.onion`
- **SHA256:** `31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502`
- **SHA256:** `ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22`
- **SHA256:** `8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4`
- **SHA256:** `bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc`
- **SHA256:** `6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f`
- **SHA256:** `589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880`
- **SHA256:** `7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245`
- **SHA256:** `5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241`
- **SHA256:** `60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6`
- **SHA256:** `6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141`
- **SHA256:** `571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b`
- **SHA256:** `82eb1910488657c78bef6879908526a2a2c6c31ab2f0517fcc5f3f6aa588b513`
- **SHA256:** `eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc`
- **SHA256:** `63e0d4e861048f581c9e5c64b28a053eb0023d58eebf2b943868d5f68a67a8b7`
- **SHA256:** `a0ceb258924ef004fa4efeef4bc0a86012afdb858e855ed14f1bbd31ca2e42f5`
- **SHA256:** `c41ab33986921c812c51e7a86bd3fd0691f5bba925fae612f1b717afaa2fe0ef`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
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
  - CVE(s): `CVE-2023-3519`, `CVE-2023-4966`, `CVE-2024-4885`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.131.41.207`, `185.68.93.122`, `185.68.93.233`, `31.41.44.202`, `incapt.su`, `inccdn1.lol`, `inccdn2.lol`, `inccdn3new.lol` _(+12 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502`, `ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22`, `8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4`, `bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc`, `6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f`, `589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880`, `7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245`, `5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241` _(+8 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
