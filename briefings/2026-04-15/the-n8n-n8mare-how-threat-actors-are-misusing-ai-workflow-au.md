<!-- curated:true -->
# [HIGH] The n8n n8mare: How Threat Actors Are Misusing AI Workflow Automation

**Source:** Cisco Talos
**Published:** 2026-04-15
**Article:** https://blog.talosintelligence.com/the-n8n-n8mare/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Talos identified increased phishing-and-malware abuse of **n8n**, an open-source AI-workflow / automation platform similar to Zapier and Make. Activity tracked **October 2025 — March 2026**. The pattern:

- Attackers spin up free / low-cost **n8n cloud workspaces** (`<tenant>.app.n8n.cloud`) — visually-credible URLs that pass casual inspection.
- Phishing emails contain n8n-cloud links that **execute attacker-controlled workflow** (URL redirects, credential harvest, file delivery).
- The n8n-cloud subdomain inherits **TLS, sender-domain reputation, and corporate-allowlist trust** that an attacker's own domain wouldn't have.
- Some workflows chain n8n → another legitimate platform (Zoho, OneDrive impersonation) for further trust laundering.

This is the **continuation of the SaaS-trust-laundering pattern** also seen with Vercel, Square, Cloudflare Pages, and (per other briefings this month) Cursor / VS Code Tunnels. It works because **defenders allowlist `*.app.n8n.cloud`**, so the malicious workflow runs in trusted territory.

We've kept severity **HIGH** because:
- n8n / Zapier / Make are increasingly common in enterprise — your users **already use them legitimately**, so blocking the entire domain is unrealistic.
- The detection has to be at the **link-content** layer (where does the n8n workflow ultimately redirect / fetch from), not the **destination-domain** layer.

## Indicators of Compromise (high-fidelity only)

- **Domains (defanged):**
  - n8n-cloud workspaces used by attackers: `tti.app.n8n.cloud`, `pagepoinnc.app.n8n.cloud`, `monicasue.app.n8n.cloud`
  - Trust-laundering hops: `centrastage.net`, `onedrivedownload.zoholandingpage.com`, `majormetalcsorp.com`
- **SHA256 hashes** (stage-2 binaries):
  - `93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a`
  - `7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0`

## MITRE ATT&CK (analyst-validated)

- **T1566.002** — Spearphishing Link
- **T1583.006** — Acquire Infrastructure: Web Services (free n8n cloud tenant)
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1102.002** — Web Service: Bidirectional Communication (the workflow itself is the C2)
- **T1656** — Impersonation (legitimate-platform branding)
- **T1071.001** — Web Protocols
- **T1027** — Obfuscated Files or Information
- **T1204.001** — User Execution: Malicious Link

## Recommended SOC actions (priority-ordered)

1. **Hunt URL clicks to `*.app.n8n.cloud`** in your email-click telemetry for the past 90 days. Most legitimate enterprise n8n usage is from a small set of internal users — anomalous external click events stand out.
2. **Block the 6 specific domains** at egress. The n8n-cloud subdomains can be added as exact-match blocks without breaking legitimate `app.n8n.cloud` use.
3. **Hash-match the 2 SHA256** stage-2 binaries against EDR file/process events.
4. **Tune your email gateway** to inspect n8n-cloud / make.com / zapier.com URLs more deeply — these are now equivalent in risk to direct attacker domains.
5. **Audit n8n-cloud usage internally**: if you sanction n8n, document which users / workflows; surface unsanctioned usage.
6. **Apply this lesson broadly**: every "AI workflow / automation platform" your users adopt is a candidate trust-laundering channel. Make.com, Zapier, Pipedream, Lindy, Tray.io — same pattern, same defensive posture.

## Splunk SPL — URL clicks to n8n-cloud (and similar SaaS automation)

```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered"
      AND (All_Email.url="*.app.n8n.cloud*"
        OR All_Email.url="*.make.com*"
        OR All_Email.url="*.zapier.com*"
        OR All_Email.url="*.pipedream.com*")
    by All_Email.recipient, All_Email.url, All_Email.subject, All_Email.src_user
| sort - count
```

## Splunk SPL — direct hits to article IOC domains

```spl
| tstats `summariesonly` count
    from datamodel=Web
    where Web.url="*tti.app.n8n.cloud*"
       OR Web.url="*pagepoinnc.app.n8n.cloud*"
       OR Web.url="*monicasue.app.n8n.cloud*"
       OR Web.dest IN ("centrastage.net","onedrivedownload.zoholandingpage.com","majormetalcsorp.com")
    by Web.src, Web.dest, Web.url, Web.user
| `drop_dm_object_name(Web)`
```

## Defender KQL — URL clicks to SaaS automation (with click-then-process correlation)

```kql
let LookbackDays = 90d;
let SaasAutomationClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | where Url has_any (".app.n8n.cloud","make.com","zapier.com","pipedream.com",
                          "tray.io","lindy.ai","retool.com")
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url;
SaasAutomationClicks
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName in~ ("powershell.exe","cmd.exe","mshta.exe")
    | project DeviceName, AccountName, ExecTime = Timestamp, ProcessCommandLine
  ) on $left.AccountUpn == $right.AccountName
| where ExecTime between (ClickTime .. ClickTime + 60m)
| project ClickTime, AccountUpn, Url, ExecTime, DeviceName, ProcessCommandLine
| order by ClickTime desc
```

## Defender KQL — direct IOC hits

```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any (
    "tti.app.n8n.cloud","pagepoinnc.app.n8n.cloud","monicasue.app.n8n.cloud",
    "centrastage.net","onedrivedownload.zoholandingpage.com","majormetalcsorp.com")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName
| order by Timestamp desc
```

## Defender KQL — hash match (managed endpoints)

```kql
let n8nMareHashes = dynamic([
    "93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a",
    "7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0"]);
union DeviceFileEvents, DeviceProcessEvents
| where Timestamp > ago(60d)
| where SHA256 in~ (n8nMareHashes)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

## Why this matters for your SOC

n8n abuse is **another data point on the SaaS-trust-laundering trend** — a generic problem your defender stack is structurally weak against. Talos's 2025-2026 telemetry confirms it's not theoretical; attackers are running real campaigns on `*.app.n8n.cloud` today.

The strategic answer is **link-content inspection**, not domain blocking — your URL-rewrite / sandbox / safe-link tooling has to actually visit the n8n workflow URL and follow the chain to the eventual payload. That's a vendor-tooling configuration question (Microsoft Defender for Office 365 Safe Links, Proofpoint URL Defense, etc.). If your gateway just allowlists `*.app.n8n.cloud` and lets the click through, the attacker wins on first contact.

The 6 domains + 2 hashes are an immediate IOC drop. Block them today; audit your URL-rewrite policy this quarter.

The n8n n8mare: How threat actors are misusing AI workflow automation 
By 
Sean Gallagher , 
Omid Mirzaei 
Wednesday, April 15, 2026 06:00
Threat Spotlight
Cisco Talos research has uncovered agentic AI workflow automation platform abuse in emails. Recently, we identified an increase in the number of emails that abuse n8n, one of these platforms, from as early as October 2025 through March 2026. 
In this blog, Talos provides concrete examples of how threat actors are weaponizing legitimate automa…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `tti.app.n8n.cloud`
- **Domain (defanged):** `centrastage.net`
- **Domain (defanged):** `onedrivedownload.zoholandingpage.com`
- **Domain (defanged):** `majormetalcsorp.com`
- **Domain (defanged):** `pagepoinnc.app.n8n.cloud`
- **Domain (defanged):** `monicasue.app.n8n.cloud`
- **SHA256:** `93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a`
- **SHA256:** `7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — PowerShell
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software

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

### Suspicious URL click in email — phishing landing page

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.action="delivered" AND All_Email.url!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.url, All_Email.subject
| rex field=All_Email.url "https?://(?<email_domain>[^/]+)"
| join type=inner email_domain
    [| tstats `summariesonly` count
        from datamodel=Web
        where Web.action="allowed"
        by Web.src, Web.dest, Web.url, Web.user
     | rex field=Web.url "https?://(?<email_domain>[^/]+)"]
| stats values(All_Email.subject) as subject, values(Web.url) as clicked_url,
        earliest(_time) as first_seen, latest(_time) as last_seen
        by All_Email.recipient, email_domain
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let DeliveredEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, Subject, SenderFromAddress, RecipientEmailAddress,
              EmailTimestamp = Timestamp;
EmailUrlInfo
| where Timestamp > ago(LookbackDays)
| join kind=inner DeliveredEmails on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ClickAllowed"
    | project Url, ClickTimestamp = Timestamp, AccountUpn, IPAddress
  ) on Url
| project ClickTimestamp, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, IPAddress
| order by ClickTimestamp desc
```

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `tti.app.n8n.cloud`, `centrastage.net`, `onedrivedownload.zoholandingpage.com`, `majormetalcsorp.com`, `pagepoinnc.app.n8n.cloud`, `monicasue.app.n8n.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a`, `7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
