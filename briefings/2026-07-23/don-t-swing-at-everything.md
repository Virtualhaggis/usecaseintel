# [CRIT] Don’t swing at everything

**Source:** Cisco Talos
**Published:** 2026-07-23
**Article:** https://blog.talosintelligence.com/dont-swing-at-everything/

## Threat Profile

Don’t swing at everything 
By 
Thorsten Rosendahl 
Thursday, July 23, 2026 14:00
Threat Source newsletter
Welcome to this week’s edition of the Threat Source newsletter. 
Lately I've found myself thinking a lot about the Australian TV series Mr. Inbetween (IMDb 8.7/10) — not because I'm a hitman for hire, but because I literally feel in-between. Specifically, in-between what I'd call the "pre-Mythos" and “post-Mythos” eras. We've crossed a capability threshold, and it's not just one model family…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-60137`
- **CVE:** `CVE-2026-63030`
- **IPv4 (defanged):** `172.86.126.18`
- **Domain (defanged):** `is-01-ast.ols-img-12.workers.dev`
- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`
- **SHA256:** `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba`
- **SHA256:** `633bd79d1efd3730234d907a2a0d98e3e253a5f0e222e4e4bf3badb3fd6aea0a`
- **SHA256:** `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `38de5b216c33833af710e88f7f64fc98`
- **MD5:** `dbd8dbecaa80795c135137d69921fdba`
- **MD5:** `770dbe473180366d7b539ff2c188e551`
- **MD5:** `c2efb2dcacba6d3ccc175b6ce1b7ed0a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1205** — Traffic Signaling
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1090.001** — Proxy: Internal Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### curl.exe downloading MSI payload into ProgramData (msaRAT delivery)

`UC_45_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl.exe Processes.process="*.msi*" Processes.process="*ProgramData*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has ".msi"
| where ProcessCommandLine has "ProgramData"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### msiexec executing MSI masquerading as Windows update from ProgramData

`UC_45_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=msiexec.exe Processes.process="*ProgramData*" Processes.process="*.msi*" (Processes.process="*update*" OR Processes.process="*patch*" OR Processes.process="*windows*" OR Processes.process="*KB*") by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "ProgramData"
| where ProcessCommandLine has ".msi"
| where ProcessCommandLine has_any ("update","patch","windows","KB")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Chrome/Edge launched with --remote-debugging-port by non-browser parent (CDP abuse)

`UC_45_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=chrome.exe OR Processes.process_name=msedge.exe) Processes.process="*--remote-debugging-port*" NOT (Processes.parent_process_name IN (explorer.exe,chrome.exe,msedge.exe,firefox.exe)) by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("chrome.exe","msedge.exe")
| where ProcessCommandLine has "--remote-debugging-port"
| where InitiatingProcessFileName !in~ ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","code.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Plain-HTTP over port 443 to msaRAT delivery IP 172.86.126.18

`UC_45_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="172.86.126.18" All_Traffic.dest_port=443 by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "172.86.126.18"
| where RemotePort == 443 or ActionType == "HttpConnectionInspected"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, ActionType, Protocol
| order by Timestamp desc
```

### Browser contacting msaRAT WebRTC signaling relay (workers.dev Cloudflare Worker)

`UC_45_13` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="is-01-ast.ols-img-12.workers.dev" OR All_Traffic.url="*is-01-ast.ols-img-12.workers.dev*" by All_Traffic.src All_Traffic.dest All_Traffic.app All_Traffic.url
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "is-01-ast.ols-img-12.workers.dev"
 | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "DnsQueryResponse"
 | where RemoteUrl has "is-01-ast.ols-img-12.workers.dev"
 | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl)
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

### Article-specific behavioural hunt — Don’t swing at everything

`UC_45_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Don’t swing at everything ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","secoh-qad.exe","server_tcp.exe","tmp00055df5.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","secoh-qad.exe","server_tcp.exe","tmp00055df5.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Don’t swing at everything
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "secoh-qad.exe", "server_tcp.exe", "tmp00055df5.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "secoh-qad.exe", "server_tcp.exe", "tmp00055df5.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `172.86.126.18`, `is-01-ast.ols-img-12.workers.dev`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-60137`, `CVE-2026-63030`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`, `e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba`, `633bd79d1efd3730234d907a2a0d98e3e253a5f0e222e4e4bf3badb3fd6aea0a`, `90b1456cdbe6bc2779ea0b4736ed9a998a71ae37390331b6ba87e389a49d3d59`, `2915b3f8b703eb744fc54c81f4a9c67f`, `38de5b216c33833af710e88f7f64fc98`, `dbd8dbecaa80795c135137d69921fdba` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 14 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
