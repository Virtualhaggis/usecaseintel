# [CRIT] Malicious PyPI Packages spellcheckpy and spellcheckerpy Deliver Python RAT

**Source:** Aikido
**Published:** 2026-01-22
**Article:** https://www.aikido.dev/blog/malicious-pypi-packages-spellcheckpy-and-spellcheckerpy-deliver-python-rat

## Threat Profile

Blog Vulnerabilities & Threats Malicious PyPI Packages spellcheckpy and spellcheckerpy Deliver Python RAT Malicious PyPI Packages spellcheckpy and spellcheckerpy Deliver Python RAT Written by Charlie Eriksen Published on: Jan 23, 2026 On January 20th and 21st, 2026, our malware detection pipeline flagged two new PyPI packages: spellcheckerpy and spellcheckpy . Both claimed to be the legitimate author of pyspellchecker library. Both are linked to his real GitHub repo.
They weren't his.
Hidden ins…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `172.86.73.139`
- **Domain (defanged):** `updatenet.work`
- **Domain (defanged):** `dothebest.store`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573** — Encrypted Channel
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1564.010** — Hide Artifacts: Process Argument Spoofing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] spellcheckpy/spellcheckerpy RAT C2 callback to updatenet.work (172.86.73.139)

`UC_471_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user_agent) as user_agents from datamodel=Web where Web.url="*updatenet.work*" OR Web.site IN ("updatenet.work","www.updatenet.work") OR Web.dest="172.86.73.139" by Web.src Web.user Web.dest Web.site | `drop_dm_object_name(Web)` | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where Network_Traffic.dest_ip="172.86.73.139" OR Network_Traffic.dest="172.86.73.139" by Network_Traffic.src Network_Traffic.dest_ip Network_Traffic.dest_port Network_Traffic.app | `drop_dm_object_name(Network_Traffic)` ] | append [ | tstats summariesonly=true count from datamodel=Network_Resolution where Network_Resolution.query IN ("updatenet.work","*.updatenet.work","dothebest.store","*.dothebest.store") by Network_Resolution.src Network_Resolution.query Network_Resolution.answer | `drop_dm_object_name(Network_Resolution)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["updatenet.work","dothebest.store"]);
let _c2_ips = dynamic(["172.86.73.139"]);
let _c2_urls = dynamic(["updatenet.work/settings/history.php","updatenet.work/update1.php"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (isnotempty(RemoteUrl) and (RemoteUrl has_any (_c2_domains) or RemoteUrl has_any (_c2_urls)))
   or RemoteIP in (_c2_ips)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType
| order by Timestamp desc
```

### [LLM] Installation footprint of malicious PyPI packages spellcheckpy / spellcheckerpy

`UC_471_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process="*spellcheckpy*" OR Processes.process="*spellcheckerpy*") AND (Processes.process_name IN ("pip","pip.exe","pip3","pip3.exe","python","python.exe","python3","python3.exe","uv","uv.exe","poetry","poetry.exe","pipx","pipx.exe") OR Processes.parent_process_name IN ("pip","pip.exe","pip3","pip3.exe","python","python.exe","python3","python3.exe")) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*spellcheckpy*" OR Filesystem.file_path="*spellcheckerpy*" OR Filesystem.file_path="*/spellcheckpy/resources/eu.json.gz" OR Filesystem.file_path="*\\spellcheckpy\\resources\\eu.json.gz" OR Filesystem.file_path="*/spellcheckerpy/resources/eu.json.gz") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _bad_packages = dynamic(["spellcheckpy","spellcheckerpy"]);
union isfuzzy=true
    ( DeviceProcessEvents
        | where Timestamp > ago(30d)
        | where ProcessCommandLine has_any (_bad_packages)
        | where FileName in~ ("pip","pip.exe","pip3","pip3.exe","python","python.exe","python3","python3.exe","uv","uv.exe","poetry","poetry.exe","pipx","pipx.exe")
           or InitiatingProcessFileName in~ ("pip","pip.exe","pip3","pip3.exe","python","python.exe","python3","python3.exe")
           or ProcessCommandLine has_any ("pip install","pip3 install","uv pip install","poetry add","pipx install")
        | project Timestamp, DeviceName, AccountName, EvidenceType="ProcessExecution",
                  FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine ),
    ( DeviceFileEvents
        | where Timestamp > ago(30d)
        | where (FolderPath has_any (_bad_packages) or FileName has_any (_bad_packages))
           or (FolderPath has_any ("spellcheckpy\\resources","spellcheckpy/resources","spellcheckerpy\\resources","spellcheckerpy/resources")
               and FileName =~ "eu.json.gz")
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, EvidenceType="FileWrite",
                  FileName=FileName, ProcessCommandLine=InitiatingProcessCommandLine,
                  InitiatingProcessFileName, InitiatingProcessCommandLine=FolderPath )
| order by Timestamp desc
```

### [LLM] Python spawning python with stdin payload (-) and detached session - spellcheckpy RAT stage-2

`UC_471_12` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("python","python.exe","python3","python3.exe","python3.9","python3.10","python3.11","python3.12")) AND (Processes.process_name IN ("python","python.exe","python3","python3.exe","python3.9","python3.10","python3.11","python3.12")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | rex field=process "(?i)python[0-9.]*(?:\.exe)?\s+(?<argv>.*)$" | where match(argv, "^-\s*$") OR match(argv, "^- ") OR argv="-" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _py_names = dynamic(["python","python.exe","python3","python3.exe","python3.9","python3.10","python3.11","python3.12","python3.13"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (_py_names)
| where FileName in~ (_py_names)
| extend CmdTrim = trim(@"\s+", tostring(ProcessCommandLine))
| where CmdTrim matches regex @"(?i)(^|[\\/\"' ])python[0-9.]*(\.exe)?[\"']?\s+-\s*$"
| project Timestamp, DeviceName, AccountName,
          ParentImage=InitiatingProcessFolderPath, ParentCmd=InitiatingProcessCommandLine,
          ChildImage=FolderPath, ChildCmd=ProcessCommandLine,
          InitiatingProcessParentFileName
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has_any ("updatenet.work","dothebest.store") or RemoteIP == "172.86.73.139"
    | project DeviceId, NetTime=Timestamp, RemoteUrl, RemoteIP
   ) on $left.DeviceName == $right.DeviceId
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Malicious PyPI Packages spellcheckpy and spellcheckerpy Deliver Python RAT

`UC_471_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious PyPI Packages spellcheckpy and spellcheckerpy Deliver Python RAT ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py","utils.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("__init__.py","utils.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious PyPI Packages spellcheckpy and spellcheckerpy Deliver Python RAT
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py", "utils.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("__init__.py", "utils.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `172.86.73.139`, `updatenet.work`, `dothebest.store`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
