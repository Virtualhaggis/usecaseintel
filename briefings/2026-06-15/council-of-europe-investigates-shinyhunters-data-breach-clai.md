# [HIGH] Council of Europe investigates ShinyHunters data breach claims

**Source:** BleepingComputer
**Published:** 2026-06-15
**Article:** https://www.bleepingcomputer.com/news/security/council-of-europe-investigates-shinyhunters-data-breach-claims/

## Threat Profile

Council of Europe investigates ShinyHunters data breach claims 
By Sergiu Gatlan 
June 15, 2026
12:37 PM
0 


The Council of Europe, the continent's oldest intergovernmental body, is probing claims of a data breach made by the ShinyHunters extortion group over the weekend.


As Europe's leading human rights organization, the Council represents 46 European member states and a population of over 700 million people, promoting democracy and the rule of law across Europe and beyond.


When aske…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35273`
- **IPv4 (defanged):** `142.11.200.186`
- **IPv4 (defanged):** `142.11.200.187`
- **IPv4 (defanged):** `142.11.200.188`
- **IPv4 (defanged):** `142.11.200.189`
- **IPv4 (defanged):** `142.11.200.190`
- **IPv4 (defanged):** `108.174.202.99`
- **IPv4 (defanged):** `176.120.22.24`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1219** — Remote Access Software
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Dynamic Resolution: Domain Generation Algorithms
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound fetch of MeshCentral agent from ShinyHunters staging IPs (142.11.200.186-190)

`UC_3_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.src_ip) as src_ip values(All_Traffic.app) as app values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") AND All_Traffic.dest_port IN (80,443,4433,8080) by All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24")
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemotePort in (80,443,4433,8080)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName
| order by Timestamp desc
```

### C2 callback to azurenetfiles.net (ShinyHunters MeshCentral WSS endpoint)

`UC_3_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query IN ("azurenetfiles.net","*.azurenetfiles.net","azurefilenet.com","*.azurefilenet.com","azure-netfiles.com","*.azure-netfiles.com") by DNS.query, DNS.src | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Typosquats = dynamic(["azurenetfiles.net","azurefilenet.com","azure-netfiles.com","azurenetfile.net"]);
union isfuzzy=true
(DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (Typosquats)
   or (RemoteUrl endswith ".azurenetfiles.net")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName, Source="NetworkEvents"),
(DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has_any (Typosquats) or RemoteUrl endswith ".azurenetfiles.net"
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP=tostring(parse_json(AdditionalFields).IPAddresses), RemotePort=int(null), RemoteUrl, InitiatingProcessAccountName, Source="DnsQueryResponse")
| order by Timestamp desc
```

### PeopleSoft Environment Management endpoint exploit attempt from ShinyHunters scanner IPs (CVE-2026-35273)

`UC_3_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.status) as status values(Web.dest) as dest from datamodel=Web.Web where (Web.url="*/psemhub/hub*" OR Web.url="*/psemagent*" OR Web.url="*/PSEMHUB/*" OR Web.url="*/cs/*/cache/*" OR Web.url="*/peoplesoft*" OR Web.url="*/psp/*/EMPLOYEE/*") AND Web.src IN ("142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24") by Web.src, Web.dest, Web.url, Web.http_method | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ScannerIPs = dynamic(["142.11.200.186","142.11.200.187","142.11.200.188","142.11.200.189","142.11.200.190","108.174.202.99","176.120.22.24"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where RemoteIP in (ScannerIPs)
| where LocalPort in (80,443,8000,8080,8443)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","tomcat9.exe","java.exe")
| project Timestamp, DeviceName, DeviceId, RemoteIP, LocalPort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35273`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.200.186`, `142.11.200.187`, `142.11.200.188`, `142.11.200.189`, `142.11.200.190`, `108.174.202.99`, `176.120.22.24`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
