# [CRIT] Hackers Use Single-Letter Go Module Typosquat to Deploy DNS-Based Backdoor

**Source:** Cyber Security News
**Published:** 2026-05-20
**Article:** https://cybersecuritynews.com/hackers-use-single-letter-go-module-typosquat/

## Threat Profile

Home Cyber Security News 
Hackers Use Single-Letter Go Module Typosquat to Deploy DNS-Based Backdoor 
By Tushar Subhra Dutta 
May 20, 2026 




A seemingly innocent typo in a Go module name has been quietly serving a live backdoor for nearly three years. Security researchers uncovered a malicious package called  github.com/shopsprint/decimal  that impersonates the popular  github.com/shopspring/decimal  library, differing by just a single letter in its name. 
The package went live in 2017 bu…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33017`
- **Domain (defanged):** `dnslog-cdn-images.freemyip.com`
- **Domain (defanged):** `freemyip.com`
- **SHA256:** `dd9c0268c8944e6ddf90d4d0c81aa843785b7a9ee965faa635841ed9fc0ba086`
- **SHA256:** `387d7ea5ca733b1e7219c943f4b461877a8df0148adfef42b1538b6c398fbb41`
- **SHA1:** `2f0ee073c6f29d66188a845592029c9b52528f04`
- **SHA1:** `fd26f4ca4746ee390e22043a5e19ebf2b7fcd1f9`
- **MD5:** `e3c6ce0440d9acd0f1cef1f0da3cdb5d`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `dnslog-cdn-images.freemyip.com`, `freemyip.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33017`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `dd9c0268c8944e6ddf90d4d0c81aa843785b7a9ee965faa635841ed9fc0ba086`, `387d7ea5ca733b1e7219c943f4b461877a8df0148adfef42b1538b6c398fbb41`, `2f0ee073c6f29d66188a845592029c9b52528f04`, `fd26f4ca4746ee390e22043a5e19ebf2b7fcd1f9`, `e3c6ce0440d9acd0f1cef1f0da3cdb5d`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
