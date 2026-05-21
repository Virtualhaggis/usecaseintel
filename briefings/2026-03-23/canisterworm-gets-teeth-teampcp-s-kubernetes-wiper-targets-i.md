# [HIGH] CanisterWorm Gets Teeth: TeamPCP's Kubernetes Wiper Targets Iran

**Source:** Aikido
**Published:** 2026-03-23
**Article:** https://www.aikido.dev/blog/teampcp-stage-payload-canisterworm-iran

## Threat Profile

Blog Vulnerabilities & Threats TeamPCP deploys CanisterWorm on NPM following Trivy compromise TeamPCP deploys CanisterWorm on NPM following Trivy compromise Written by Charlie Eriksen Published on: Mar 20, 2026 On 20 Mar 2026, 20:45 UTC, we detected a large number of packages being compromised on NPM with a new worm that hasn't been observed before. We're calling this specific attack CanisterWorm, because it makes use of an ICP Canister for its C2 dead-drop, which is the first time we've seen in…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
- **SHA256:** `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b`
- **SHA256:** `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba`
- **SHA256:** `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a`
- **SHA256:** `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926`
- **SHA256:** `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152`
- **SHA256:** `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7`
- **SHA256:** `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1102.002** — Web Service: Bidirectional Communication
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1102** — Web Service
- **T1610** — Deploy Container
- **T1611** — Escape to Host
- **T1485** — Data Destruction
- **T1561.002** — Disk Wipe: Disk Structure Wipe
- **T1529** — System Shutdown/Reboot
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DNS/HTTP egress to CanisterWorm ICP canister C2 (tdtqy-oyaaa-aaaae-af2dq-cai)

`UC_403_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where Network_Resolution.query="*tdtqy-oyaaa-aaaae-af2dq-cai*" OR Network_Resolution.query="*.raw.icp0.io" by Network_Resolution.src Network_Resolution.dest Network_Resolution.query | `drop_dm_object_name(Network_Resolution)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*tdtqy-oyaaa-aaaae-af2dq-cai*" by Web.src Web.dest Web.url | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("tdtqy-oyaaa-aaaae-af2dq-cai", ".raw.icp0.io")
   or AdditionalFields has "tdtqy-oyaaa-aaaae-af2dq-cai"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          RemoteIP, RemotePort, RemoteUrl, LocalIP
| order by Timestamp desc
```

### [LLM] Cloudflare-tunnel curl-piped Python stager (kamikaze.sh / kube.py)

`UC_403_8` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*kamikaze.sh*" OR Processes.process="*kube.py*" OR Processes.process="*souls-entire-defined-routes.trycloudflare.com*" OR Processes.process="*championships-peoples-point-cassette.trycloudflare.com*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("kamikaze.sh","kube.py","souls-entire-defined-routes.trycloudflare.com","championships-peoples-point-cassette.trycloudflare.com")
   or InitiatingProcessCommandLine has_any ("kamikaze.sh","kube.py","souls-entire-defined-routes.trycloudflare.com","championships-peoples-point-cassette.trycloudflare.com")
| where FileName in~ ("curl","wget","python","python3","bash","sh","dash")
     or InitiatingProcessFileName in~ ("curl","wget","python","python3","bash","sh","dash")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Malicious privileged DaemonSet apply in kube-system (host-provisioner-iran / host-provisioner-std / kamikaze)

`UC_403_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="kubectl" AND Processes.process="*apply*" AND (Processes.process="*host-provisioner-iran*" OR Processes.process="*host-provisioner-std*" OR Processes.process="*kamikaze*") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "kubectl" or InitiatingProcessFileName =~ "kubectl")
| where ProcessCommandLine has_any ("host-provisioner-iran","host-provisioner-std","kamikaze")
   or (ProcessCommandLine has "apply" and ProcessCommandLine has "kube-system" and ProcessCommandLine has "DaemonSet")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Host-root mount wiper: chroot /mnt/host reboot -f or rm -rf / --no-preserve-root

`UC_403_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*rm -rf / --no-preserve-root*" OR (Processes.process="*chroot*" AND Processes.process="*/mnt/host*" AND Processes.process="*reboot*") OR (Processes.process="*find /mnt/host*" AND Processes.process="*-exec rm -rf*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "rm -rf / --no-preserve-root"
   or (ProcessCommandLine has "chroot" and ProcessCommandLine has "/mnt/host" and ProcessCommandLine has "reboot")
   or (ProcessCommandLine has "find /mnt/host" and ProcessCommandLine has "-exec rm -rf")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### [LLM] CanisterWorm persistence: pglog/pg_state/internal-monitor systemd unit and /tmp/pglog drop

`UC_403_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/etc/systemd/system/pglog.service" OR Filesystem.file_path="/etc/systemd/system/pg_state.service" OR Filesystem.file_path="/etc/systemd/system/internal-monitor.service" OR Filesystem.file_path="/tmp/pglog/*" OR (Filesystem.file_name="runner.py" AND Filesystem.file_path="/tmp/*")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | append [| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.process="*systemctl enable --now pglog*" OR Processes.process="*systemctl enable --now pg_state*" OR Processes.process="*systemctl enable --now internal-monitor*") by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
union isfuzzy=true
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where (FolderPath has "/etc/systemd/system/" and FileName in~ ("pglog.service","pg_state.service","internal-monitor.service"))
        or FolderPath startswith "/tmp/pglog"
        or (FolderPath has "/tmp/" and FileName =~ "runner.py")
    | extend Evt = "FileWrite", Detail = strcat(FolderPath, FileName), Cmd = InitiatingProcessCommandLine, Bin = InitiatingProcessFileName),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("systemctl enable --now pglog","systemctl enable --now pg_state","systemctl enable --now internal-monitor")
         or (ProcessCommandLine has "Description=System Monitor" and ProcessCommandLine has "ExecStart=/usr/bin/python3")
    | extend Evt = "ProcessExec", Detail = ProcessCommandLine, Cmd = ProcessCommandLine, Bin = FileName)
| project Timestamp, DeviceName, Evt, Detail, Bin, Cmd
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

### Article-specific behavioural hunt — CanisterWorm Gets Teeth: TeamPCP's Kubernetes Wiper Targets Iran

`UC_403_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — CanisterWorm Gets Teeth: TeamPCP's Kubernetes Wiper Targets Iran ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","deploy.js","service.py","sysmon.py","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/python3*" OR Filesystem.file_path="*/tmp/pglog*" OR Filesystem.file_path="*/tmp/.pg_state*" OR Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/etc/npmrc*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("node.js","deploy.js","service.py","sysmon.py","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — CanisterWorm Gets Teeth: TeamPCP's Kubernetes Wiper Targets Iran
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "deploy.js", "service.py", "sysmon.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/python3", "/tmp/pglog", "/tmp/.pg_state", "/usr/bin/env", "/etc/npmrc", "/dev/null") or FileName in~ ("node.js", "deploy.js", "service.py", "sysmon.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b`, `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba`, `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a`, `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926`, `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152`, `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7`, `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
