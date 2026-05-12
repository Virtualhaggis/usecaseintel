# [HIGH] Magecart Hackers Abuse Google Tag Manager to Inject Credit Card Skimmers

**Source:** Cyber Security News
**Published:** 2026-05-12
**Article:** https://cybersecuritynews.com/magecart-hackers-abuse-google-tag-manager/

## Threat Profile

Home Cyber Security News 
Magecart Hackers Abuse Google Tag Manager to Inject Credit Card Skimmers 
By Tushar Subhra Dutta 
May 12, 2026 
Online shoppers have long been targets of digital theft, but a recent wave of attacks has raised the stakes in a troubling new way. Hackers tied to the notorious Magecart group are now hiding credit card skimmers inside Google Tag Manager (GTM) containers, turning a widely trusted web tool into a silent weapon against unsuspecting online shoppers. 
Google Tag …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-41940`
- **IPv4 (defanged):** `31.220.21.211`
- **IPv4 (defanged):** `31.220.21.240`
- **IPv4 (defanged):** `62.72.7.89`
- **IPv4 (defanged):** `62.72.7.90`
- **Domain (defanged):** `cdn.sketchinsightswatch.com`
- **Domain (defanged):** `cdn.colorpalettemetrics.com`
- **Domain (defanged):** `gtm-statistlc.com`
- **Domain (defanged):** `goqle-analytics.com`
- **Domain (defanged):** `webstatlstics.com`
- **Domain (defanged):** `lgstd.io`
- **Domain (defanged):** `cdn.artisticpatterndata.com`
- **Domain (defanged):** `cdn.visualartexplorer.com`
- **Domain (defanged):** `cdn.picturedataminer.com`
- **Domain (defanged):** `cdn.paintedworldstats.com`
- **Domain (defanged):** `cdn.drawinginfopro.com`
- **Domain (defanged):** `cdn.artistictrendsmap.com`
- **Domain (defanged):** `cdn.sketchanalyticsvault.com`
- **Domain (defanged):** `cdn.colorschemeobserver.com`
- **Domain (defanged):** `cdn.artdataharvest.com`
- **Domain (defanged):** `cdn.gallerytrendstracker.com`
- **Domain (defanged):** `cdn.picturetrendsmonitor.com`
- **Domain (defanged):** `cdn.brushstrokemetrics.com`
- **Domain (defanged):** `cdn.imagepatternprofiler.com`
- **Domain (defanged):** `cdn.artisticexpressiondb.com`
- **Domain (defanged):** `cdn.sketchdataanalytics.com`
- **Domain (defanged):** `cdn.canvastrendstracker.com`
- **Domain (defanged):** `cdn.visualartinsights.com`
- **Domain (defanged):** `cdn.strokepatternanalysis.com`
- **Domain (defanged):** `cdn.artstattracker.com`
- **Domain (defanged):** `cdn.drawdatahub.com`
- **Domain (defanged):** `cdn.sketchmetrics.com`
- **Domain (defanged):** `cdn.paintinfoanalyzer.com`
- **Domain (defanged):** `cdn.imageinsightvault.com`
- **Domain (defanged):** `cdn.visualdatacollector.com`
- **Domain (defanged):** `cdn.artworkanalytics.com`
- **Domain (defanged):** `cdn.sketchtrendsmonitor.com`
- **Domain (defanged):** `cdn.picinfometrics.com`
- **Domain (defanged):** `cdn.drawnstatsgather.com`
- **Domain (defanged):** `cdn.artistictrendsprobe.com`
- **Domain (defanged):** `cdn.gallerydatainsight.com`
- **Domain (defanged):** `cdn.strokeanalysislab.com`
- **Domain (defanged):** `cdn.imagestatistician.com`
- **Domain (defanged):** `cdn.artprofilingtool.com`
- **Domain (defanged):** `cdn.sketchdataharbor.com`
- **Domain (defanged):** `cdn.picturetrendsdb.com`
- **Domain (defanged):** `cdn.drawninfoinspector.com`
- **Domain (defanged):** `cdn.arttrendtrackers.com`
- **Domain (defanged):** `cdn.paintedvisionsstats.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1056.001** — Input Capture: Keylogging
- **T1102** — Web Service
- **T1189** — Drive-by Compromise
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ATMZOW Magecart Skimmer Payload-Delivery Domain Egress (Nov-2023 Hostinger Batch)

`UC_27_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution where DNS.query IN ("cdn.sketchinsightswatch.com","cdn.colorpalettemetrics.com","cdn.artisticpatterndata.com","cdn.visualartexplorer.com","cdn.picturedataminer.com","cdn.paintedworldstats.com","cdn.drawinginfopro.com","cdn.artistictrendsmap.com","cdn.sketchanalyticsvault.com","cdn.colorschemeobserver.com","cdn.artdataharvest.com","cdn.gallerytrendstracker.com","cdn.picturetrendsmonitor.com","cdn.brushstrokemetrics.com","cdn.imagepatternprofiler.com","cdn.artisticexpressiondb.com","cdn.sketchdataanalytics.com","cdn.canvastrendstracker.com","cdn.visualartinsights.com","cdn.strokepatternanalysis.com","cdn.artstattracker.com","cdn.drawdatahub.com","cdn.sketchmetrics.com","cdn.paintinfoanalyzer.com","cdn.imageinsightvault.com","cdn.visualdatacollector.com","cdn.artworkanalytics.com","cdn.sketchtrendsmonitor.com","cdn.picinfometrics.com","cdn.drawnstatsgather.com","cdn.artistictrendsprobe.com","cdn.gallerydatainsight.com","cdn.strokeanalysislab.com","cdn.imagestatistician.com","cdn.artprofilingtool.com","cdn.sketchdataharbor.com","cdn.picturetrendsdb.com","cdn.drawninfoinspector.com","cdn.arttrendtrackers.com","cdn.paintedvisionsstats.com","gtm-statistlc.com","goqle-analytics.com","webstatlstics.com","lgstd.io") by DNS.query, DNS.src, DNS.dest | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | append [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src from datamodel=Network_Traffic where All_Traffic.dest IN ("31.220.21.211","31.220.21.240","62.72.7.89","62.72.7.90") by All_Traffic.dest, All_Traffic.src | `drop_dm_object_name(All_Traffic)` ] | sort - count
```

**Defender KQL:**
```kql
let _atmzow_domains = dynamic(["cdn.sketchinsightswatch.com","cdn.colorpalettemetrics.com","cdn.artisticpatterndata.com","cdn.visualartexplorer.com","cdn.picturedataminer.com","cdn.paintedworldstats.com","cdn.drawinginfopro.com","cdn.artistictrendsmap.com","cdn.sketchanalyticsvault.com","cdn.colorschemeobserver.com","cdn.artdataharvest.com","cdn.gallerytrendstracker.com","cdn.picturetrendsmonitor.com","cdn.brushstrokemetrics.com","cdn.imagepatternprofiler.com","cdn.artisticexpressiondb.com","cdn.sketchdataanalytics.com","cdn.canvastrendstracker.com","cdn.visualartinsights.com","cdn.strokepatternanalysis.com","cdn.artstattracker.com","cdn.drawdatahub.com","cdn.sketchmetrics.com","cdn.paintinfoanalyzer.com","cdn.imageinsightvault.com","cdn.visualdatacollector.com","cdn.artworkanalytics.com","cdn.sketchtrendsmonitor.com","cdn.picinfometrics.com","cdn.drawnstatsgather.com","cdn.artistictrendsprobe.com","cdn.gallerydatainsight.com","cdn.strokeanalysislab.com","cdn.imagestatistician.com","cdn.artprofilingtool.com","cdn.sketchdataharbor.com","cdn.picturetrendsdb.com","cdn.drawninfoinspector.com","cdn.arttrendtrackers.com","cdn.paintedvisionsstats.com","gtm-statistlc.com","goqle-analytics.com","webstatlstics.com","lgstd.io"]);
let _atmzow_ips = dynamic(["31.220.21.211","31.220.21.240","62.72.7.89","62.72.7.90"]);
union isfuzzy=true
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (_atmzow_domains) or RemoteIP in (_atmzow_ips)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType, Source="DeviceNetworkEvents" ),
  ( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName has_any (_atmzow_domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl=QueryName, RemoteIP=tostring(parse_json(AdditionalFields).IPAddresses), RemotePort=int(null), ActionType, Source="DeviceEvents-DNS" )
| order by Timestamp desc
```

### [LLM] Known-Malicious GTM Container ID Loaded From Web Proxy / IIS Logs (ATMZOW)

`UC_27_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.src) as src values(Web.url) as url values(Web.http_referrer) as referrer from datamodel=Web where Web.dest="*googletagmanager.com*" AND (Web.url="*GTM-WJV6J6*" OR Web.url="*GTM-TVKQ79ZS*" OR Web.url="*GTM-NTV2JTB4*" OR Web.url="*GTM-MX7L8F2M*") by Web.src, Web.dest, Web.url | `drop_dm_object_name(Web)` | rex field=url "(?<gtm_container_id>GTM-[A-Z0-9]+)" | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
let _bad_gtm = dynamic(["GTM-WJV6J6","GTM-TVKQ79ZS","GTM-NTV2JTB4","GTM-MX7L8F2M"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "googletagmanager.com"
| where RemoteUrl has_any (_bad_gtm)
| extend BadContainer = extract(@"(GTM-[A-Z0-9]+)", 1, RemoteUrl)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, BadContainer
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-41940`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `31.220.21.211`, `31.220.21.240`, `62.72.7.89`, `62.72.7.90`, `cdn.sketchinsightswatch.com`, `cdn.colorpalettemetrics.com`, `gtm-statistlc.com`, `goqle-analytics.com` _(+40 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
