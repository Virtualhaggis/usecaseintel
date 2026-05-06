# [HIGH] We Scanned 1 Million Exposed AI Services. Here's How Bad the Security Actually Is

**Source:** The Hacker News
**Published:** 2026-05-05
**Article:** https://thehackernews.com/2026/05/we-scanned-1-million-exposed-ai.html

## Threat Profile

We Scanned 1 Million Exposed AI Services. Here's How Bad the Security Actually Is 
 The Hacker News  May 05, 2026 Artificial Intelligence / API Security 
While the software industry has made genuine strides over the past few decades to deliver products securely, the furious pace of AI adoption is putting that progress at risk. Businesses are moving fast to self-host LLM infrastructure, drawn by the promise of AI as a force multiplier and the pressure to deliver more value faster. But speed is …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1133** — External Remote Services
- **T1046** — Network Service Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Internet-exposed self-hosted Ollama API (port 11434) reachable from public IPs

`UC_31_2` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.action) as action values(All_Traffic.transport) as transport values(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=11434 All_Traffic.action=allowed by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("10.0.0.0/8", src) AND NOT cidrmatch("172.16.0.0/12", src) AND NOT cidrmatch("192.168.0.0/16", src) AND NOT cidrmatch("127.0.0.0/8", src) AND NOT cidrmatch("169.254.0.0/16", src)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Inbound public-internet access to internal Ollama default port 11434
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 11434
| where ActionType in ("InboundConnectionAccepted", "ConnectionSuccess")
| where RemoteIPType == "Public"
| where not(ipv4_is_private(RemoteIP))
| where not(RemoteIP startswith "127.") and not(RemoteIP startswith "169.254.")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), ConnCount = count(), DistinctSources = dcount(RemoteIP), SampleSources = make_set(RemoteIP, 25) by DeviceName, LocalIP, LocalPort, InitiatingProcessFileName
| order by ConnCount desc
```

### [LLM] Endpoint making outbound requests to Ollama /api/generate or /api/tags on non-corporate hosts

`UC_31_3` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.user) as user values(Web.dest) as dest from datamodel=Web.Web where (Web.url="*/api/generate*" OR Web.url="*/api/tags*" OR Web.url="*/api/chat*" OR Web.url="*/api/embeddings*" OR Web.dest_port=11434) by Web.src Web.dest Web.dest_port
| `drop_dm_object_name(Web)`
| where NOT cidrmatch("10.0.0.0/8", dest) AND NOT cidrmatch("172.16.0.0/12", dest) AND NOT cidrmatch("192.168.0.0/16", dest)
| stats sum(count) as RequestCount, dcount(url) as UniqueUrls, values(url) as Urls, values(method) as Methods, min(firstTime) as firstTime, max(lastTime) as lastTime by src, dest, dest_port, user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Endpoint contacts to public Ollama API endpoints — enumeration (/api/tags) or prompt submission (/api/generate, /api/chat)
let ollama_paths = dynamic(["/api/generate", "/api/tags", "/api/chat", "/api/embeddings", "/api/show", "/api/pull"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where (RemotePort == 11434) or (RemoteUrl has_any (ollama_paths))
| where InitiatingProcessFileName !in~ ("ollama.exe", "ollama-app.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          RemoteIP, RemotePort, RemoteUrl,
          ProcessName = InitiatingProcessFileName,
          ProcessCmd = InitiatingProcessCommandLine
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Hits = count(), DistinctRemotes = dcount(RemoteIP),
            SampleUrls = make_set(RemoteUrl, 25), SampleRemotes = make_set(RemoteIP, 25),
            SampleCmds = make_set(ProcessCmd, 5)
            by DeviceName, AccountName, ProcessName
| order by Hits desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
