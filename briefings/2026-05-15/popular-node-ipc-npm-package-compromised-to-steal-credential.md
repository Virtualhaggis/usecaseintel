# [HIGH] Popular node-ipc npm package compromised to steal credentials

**Source:** BleepingComputer
**Published:** 2026-05-15
**Article:** https://www.bleepingcomputer.com/news/security/popular-node-ipc-npm-package-compromised-to-steal-credentials/

## Threat Profile

Popular node-ipc npm package compromised to steal credentials 
By Bill Toulas 
May 15, 2026
01:10 PM
0 
Hackers have injected credential-stealing malware into newly published versions of node-ipc, a popular inter-process communication package, in a new supply chain attack targeting npm.
The node-ipc package is a Node.js module that enables various processes to communicate through all forms of sockets, including Unix, Windows, UDP, TLS, and TCP.
Despite the maintainer publishing in March 2022 wea…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sh.azurestaticprovider.net`
- **Domain (defanged):** `bt.node.js`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1071.004** — Application Layer Protocol: DNS
- **T1048.003** — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1074.001** — Data Staged: Local Data Staging

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] node-ipc supply chain: DNS TXT exfil to azurestaticprovider.net / bt.node.js with xh/xd/xf labels

`UC_6_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Network_Resolution.record_type) as record_type values(Network_Resolution.src) as src values(Network_Resolution.dest) as dest from datamodel=Network_Resolution where (Network_Resolution.query="*azurestaticprovider.net" OR Network_Resolution.query="*.bt.node.js" OR Network_Resolution.query="bt.node.js" OR Network_Resolution.query="xh.*" OR Network_Resolution.query="xd.*" OR Network_Resolution.query="xf.*") by Network_Resolution.query host | `drop_dm_object_name(Network_Resolution)` | where record_type="TXT" OR query LIKE "%azurestaticprovider.net" OR query LIKE "%bt.node.js" | sort - count | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["azurestaticprovider.net","bt.node.js"]);
let _exfil_prefixes = dynamic(["xh.","xd.","xf."]);
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| extend Q  = tolower(tostring(parse_json(AdditionalFields).QueryName)),
         QT = tostring(parse_json(AdditionalFields).QueryType)
| where Q endswith "azurestaticprovider.net"
     or Q endswith "bt.node.js"
     or Q startswith "xh." or Q startswith "xd." or Q startswith "xf."
| summarize Queries = count(),
            Unique = dcount(Q),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Samples = make_set(Q, 10),
            TxtCount = countif(QT == "TXT")
            by DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine
| where Queries >= 1
| order by Queries desc
```

### [LLM] node-ipc malicious version install via npm/yarn/pnpm (9.1.6, 9.2.3, 12.0.1)

`UC_6_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm","npm.cmd","npm-cli.js","yarn","yarn.cmd","pnpm","pnpm.cmd","node.exe","node")) AND Processes.process="*node-ipc*" AND (Processes.process="*9.1.6*" OR Processes.process="*9.2.3*" OR Processes.process="*12.0.1*") by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _pkg_mgrs = dynamic(["npm","npm.cmd","npm-cli.js","yarn","yarn.cmd","pnpm","pnpm.cmd","node.exe","node"]);
let _bad_versions = dynamic(["9.1.6","9.2.3","12.0.1"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (_pkg_mgrs) or InitiatingProcessFileName in~ (_pkg_mgrs)
| where ProcessCommandLine has "node-ipc"
| where ProcessCommandLine has_any (_bad_versions)
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName,
          ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

### [LLM] Node.js process stages credential archive: tar.gz in temp followed by DNS bursts

`UC_6_10` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.process_name IN ("node.exe","node")) AND (Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*/tmp/*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*/var/folders/*") AND (Filesystem.file_name="*.tar.gz" OR Filesystem.file_name="*.tgz") by host Filesystem.user | `drop_dm_object_name(Filesystem)` | sort - lastTime | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _tmp_paths = dynamic([@"\Temp\",@"\AppData\Local\Temp\","/tmp/","/var/folders/","/private/var/folders/"]);
let TarGzInTemp = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName in~ ("node.exe","node")
    | where FolderPath has_any (_tmp_paths)
    | where FileName endswith ".tar.gz" or FileName endswith ".tgz"
    | project Timestamp, DeviceName, DeviceId,
              InitiatingProcessAccountName, InitiatingProcessCommandLine,
              FileName, FolderPath, SHA256;
let DnsBursts = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName)),
             QT = tostring(parse_json(AdditionalFields).QueryType)
    | where QT == "TXT" and (Q endswith "azurestaticprovider.net" or Q endswith "bt.node.js"
         or Q startswith "xh." or Q startswith "xd." or Q startswith "xf.")
    | summarize TxtQueries = count(), DnsFirst = min(Timestamp), DnsLast = max(Timestamp) by DeviceId;
TarGzInTemp
| join kind=leftouter DnsBursts on DeviceId
| extend DnsLinked = iff(isnotempty(DnsFirst), "yes", "no")
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

### Article-specific behavioural hunt — Popular node-ipc npm package compromised to steal credentials

`UC_6_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Popular node-ipc npm package compromised to steal credentials ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Popular node-ipc npm package compromised to steal credentials
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `sh.azurestaticprovider.net`, `bt.node.js`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
