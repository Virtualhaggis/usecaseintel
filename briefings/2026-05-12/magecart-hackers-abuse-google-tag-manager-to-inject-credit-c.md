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
Goo…

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
- **T1583.001** — Acquire Infrastructure: Domains
- **T1102** — Web Service
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1185** — Browser Session Hijacking
- **T1056.003** — Input Capture: Web Portal Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ATMZOW Magecart skimmer C2 beacon to Hostinger art-themed lookalike domains

`UC_1_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.dest) as dests values(Web.dest_ip) as dest_ips from datamodel=Web.Web where (Web.url IN ("*sketchinsightswatch.com*","*colorpalettemetrics.com*","*artisticpatterndata.com*","*visualartexplorer.com*","*picturedataminer.com*","*paintedworldstats.com*","*drawinginfopro.com*","*artistictrendsmap.com*","*sketchanalyticsvault.com*","*colorschemeobserver.com*","*artdataharvest.com*","*gallerytrendstracker.com*","*picturetrendsmonitor.com*","*brushstrokemetrics.com*","*imagepatternprofiler.com*","*artisticexpressiondb.com*","*sketchdataanalytics.com*","*canvastrendstracker.com*","*visualartinsights.com*","*strokepatternanalysis.com*","*artstattracker.com*","*drawdatahub.com*","*sketchmetrics.com*","*paintinfoanalyzer.com*","*imageinsightvault.com*","*visualdatacollector.com*","*artworkanalytics.com*","*sketchtrendsmonitor.com*","*picinfometrics.com*","*drawnstatsgather.com*","*artistictrendsprobe.com*","*gallerydatainsight.com*","*strokeanalysislab.com*","*imagestatistician.com*","*artprofilingtool.com*","*sketchdataharbor.com*","*picturetrendsdb.com*","*drawninfoinspector.com*","*arttrendtrackers.com*","*paintedvisionsstats.com*","*gtm-statistlc.com*","*goqle-analytics.com*","*webstatlstics.com*","*lgstd.io*") OR Web.dest_ip IN ("31.220.21.211","31.220.21.240","62.72.7.89","62.72.7.90")) by Web.src Web.user Web.http_user_agent Web.action | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let atmzow_domains = dynamic(["sketchinsightswatch.com","colorpalettemetrics.com","artisticpatterndata.com","visualartexplorer.com","picturedataminer.com","paintedworldstats.com","drawinginfopro.com","artistictrendsmap.com","sketchanalyticsvault.com","colorschemeobserver.com","artdataharvest.com","gallerytrendstracker.com","picturetrendsmonitor.com","brushstrokemetrics.com","imagepatternprofiler.com","artisticexpressiondb.com","sketchdataanalytics.com","canvastrendstracker.com","visualartinsights.com","strokepatternanalysis.com","artstattracker.com","drawdatahub.com","sketchmetrics.com","paintinfoanalyzer.com","imageinsightvault.com","visualdatacollector.com","artworkanalytics.com","sketchtrendsmonitor.com","picinfometrics.com","drawnstatsgather.com","artistictrendsprobe.com","gallerydatainsight.com","strokeanalysislab.com","imagestatistician.com","artprofilingtool.com","sketchdataharbor.com","picturetrendsdb.com","drawninfoinspector.com","arttrendtrackers.com","paintedvisionsstats.com","gtm-statistlc.com","goqle-analytics.com","webstatlstics.com","lgstd.io"]);
let atmzow_ips = dynamic(["31.220.21.211","31.220.21.240","62.72.7.89","62.72.7.90"]);
let net_hits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (isnotempty(RemoteUrl) and RemoteUrl has_any (atmzow_domains))
         or (RemoteIP in (atmzow_ips))
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              Process=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine,
              RemoteUrl, RemoteIP, RemotePort, Source="DeviceNetworkEvents";
let dns_hits = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QName = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where isnotempty(QName) and QName has_any (atmzow_domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              Process=InitiatingProcessFileName, ProcessCmd=InitiatingProcessCommandLine,
              RemoteUrl=QName, RemoteIP="", RemotePort=int(null), Source="DnsQueryResponse";
union net_hits, dns_hits
| order by Timestamp desc
```

### [LLM] Browser load of known-malicious ATMZOW Google Tag Manager container ID

`UC_1_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.dest) as dests values(Web.http_referrer) as referrers values(Web.http_user_agent) as user_agents from datamodel=Web.Web where Web.url="*googletagmanager.com*" AND (Web.url IN ("*GTM-WJV6J6*","*GTM-WJ6S9J6*","*GTM-TVKQ79ZS*","*GTM-NTV2JTB4*","*GTM-MX7L8F2M*","*gtm-wjv6j6*","*gtm-wj6s9j6*","*gtm-tvkq79zs*","*gtm-ntv2jtb4*","*gtm-mx7l8f2m*")) by Web.src Web.user Web.http_referrer Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let bad_gtm_ids = dynamic(["GTM-WJV6J6","GTM-WJ6S9J6","GTM-TVKQ79ZS","GTM-NTV2JTB4","GTM-MX7L8F2M"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected","ConnectionInspected")
| where isnotempty(RemoteUrl)
| where RemoteUrl has "googletagmanager.com"
| extend UrlLower = tolower(RemoteUrl)
| where UrlLower has_any ("gtm-wjv6j6","gtm-wj6s9j6","gtm-tvkq79zs","gtm-ntv2jtb4","gtm-mx7l8f2m")
| extend MatchedContainer = tostring(extract(@"(?i)(GTM-(?:WJV6J6|WJ6S9J6|TVKQ79ZS|NTV2JTB4|MX7L8F2M))", 1, RemoteUrl))
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
          Browser=InitiatingProcessFileName, BrowserCmd=InitiatingProcessCommandLine,
          RemoteUrl, MatchedContainer, RemoteIP, RemotePort
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

Severity classified as **HIGH** based on: CVE present, IOCs present, 5 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
