<!-- curated:true -->
# [CRIT] Threat Brief: Widespread Impact of the Axios Supply Chain Attack

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-04-01
**Article:** https://unit42.paloaltonetworks.com/axios-supply-chain-attack/
**Curated:** Analyst-reviewed 2026-04-28

## Threat profile

Unit 42's executive-summary brief on the **Axios npm package supply-chain attack** — Axios is one of the most-installed JavaScript HTTP clients (**~50M weekly downloads**, present in nearly every Node.js / browser project of meaningful size). The compromised release shipped a **trojanised post-install hook** that:
- Beaconed to attacker C2 (`sfrclak[.]com`, `callnrwise[.]com`).
- Pulled stage-2 from a typosquatted CDN (`packages.npm[.]org` — note: legitimate npm registry is `registry.npmjs.org`, the typosquat is `packages.npm.org`).
- Exfiltrated `.npmrc` / `.env` / cloud credentials.

The blast radius is **every CI runner, container build, and developer workstation** that ran `npm install` against the affected version range. We've kept severity **CRIT** for three reasons:
1. Axios is in the dependency graph of nearly every modern JS app — the affected population is huge.
2. The malicious package leaked **build-time secrets** (npm tokens, AWS keys, GitHub PATs, signing keys), which can be re-used long after package removal.
3. **CVE-2025-55182** is referenced — Meta React Server Components, often pinned alongside axios — exploited downstream in this campaign.

This briefing carries **27 Unit 42 IOCs** (1 IP, 3 domains, 23 SHA256 hashes) — vendor-attributed, ready to block.

Threat Research Center 
High Profile Threats 
Malware 
Malware 
Threat Brief: Widespread Impact of the Axios Supply Chain Attack 
9 min read 
Related Products Advanced DNS Security Advanced URL Filtering Advanced WildFire Cloud-Delivered Security Services Cortex Cortex Cloud Cortex XDR Cortex XSIAM Unit 42 Incident Response 
By: Unit 42 
Published: April 1, 2026 
Categories: High Profile Threats 
Malware 
Tags: API attacks 
JavaScript 
PowerShell 
Supply chain 
Trojan 
VBScript 
Executive Summar…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-55182`
- **IPv4 (defanged):** `142.11.206.73`
- **Domain (defanged):** `sfrclak.com`
- **Domain (defanged):** `packages.npm.org`
- **Domain (defanged):** `callnrwise.com`
- **SHA256:** `ad8ba560ae5c4af4758bc68cc6dcf43bae0e0bbf9da680a8dc60a9ef78e22ff7`
- **SHA256:** `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`
- **SHA256:** `cdc05cd30eb53315dadb081a7b942bb876f0d252d20e8ed4d2f36be79ee691fa`
- **SHA256:** `8449341ddc3f7fcc2547639e21e704400ca6a8a6841ae74e57c04445b1276a10`
- **SHA256:** `01c9484abc948daa525516464785009d1e7a63ffd6012b9e85b56477acc3e624`
- **SHA256:** `7b47ed28e84437aee64ffe9770d315c1b984135105f7f608a8b9579517bc0695`
- **SHA256:** `526ab39d1f56732e4e926715aaa797feb13b1ae86882ec570a4d292e7fdc3699`
- **SHA256:** `a98e04dec3a7fe507eb30c72da808bad60bc14d9d80f9770ec99c438faa85a1a`
- **SHA256:** `0d83030ab8bfba675fc1661f0756b6770be7dd80b1b718de3d68a01f2e79a5f4`
- **SHA256:** `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a`
- **SHA256:** `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668`
- **SHA256:** `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09`
- **SHA256:** `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd`
- **SHA256:** `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101`
- **SHA256:** `e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff`
- **SHA256:** `506690fcbd10fbe6f2b85b49a1fffa9d984c376c25ef6b73f764f670e932cab4`
- **SHA256:** `4465bdeaddc8c049a67a3d5ec105b2f07dae72fa080166e51b8f487516eb8d07`
- **SHA256:** `5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd`
- **SHA256:** `59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f`
- **SHA256:** `a224dd73b7ed33e0bf6a2ea340c8f8859dfa9ec5736afa8baea6225bf066b248`
- **SHA256:** `5e2ab672c3f98f21925bd26d9a9bba036b67d84fde0dfdbe2cf9b85b170cab71`
- **SHA256:** `20df0909a3a0ef26d74ae139763a380e49f77207aa1108d4640d8b6f14cab8ca`
- **SHA256:** `5b5fbc627502c5797d97b206b6dcf537889e6bea6d4e81a835e103e311690e22`
- **SHA256:** `9c64f1c7eba080b4e5ff17369ddcd00b9fe2d47dacdc61444b4cbfebb23a166c`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain

## Recommended SOC actions (priority-ordered)

1. **Block the 4 Axios IOCs at egress** today (`142.11.206.73`, `sfrclak.com`, `callnrwise.com`, `packages.npm.org`). The fourth is critical — it's a typosquat for `registry.npmjs.org` so legitimate npm traffic is unaffected.
2. **Inventory affected `axios` versions** across container images, CI configs, package-lock files. Pull from your SBOM tooling or `npm ls axios` across repos.
3. **Rotate every secret an affected CI runner / dev workstation could have touched** — npm tokens, AWS keys, GitHub PATs, signing keys, cloud-warehouse creds. Even if the install was on a now-decommissioned runner, the secret was harvested.
4. **Hash-match the 23 SHA256 stage-2 binaries** against `DeviceFileEvents` / `DeviceProcessEvents` (template below).
5. **Hunt outbound from `node.exe` / `npm.exe` to non-registry destinations** for the affected window.
6. **Pin to digest, not tag, going forward** for npm packages where supported (`overrides` + lockfile integrity hashes).

## Kill chain phases observed

_(none detected from narrative keywords — manual mapping above)_

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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.11.206.73`, `sfrclak.com`, `packages.npm.org`, `callnrwise.com`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-55182`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ad8ba560ae5c4af4758bc68cc6dcf43bae0e0bbf9da680a8dc60a9ef78e22ff7`, `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`, `cdc05cd30eb53315dadb081a7b942bb876f0d252d20e8ed4d2f36be79ee691fa`, `8449341ddc3f7fcc2547639e21e704400ca6a8a6841ae74e57c04445b1276a10`, `01c9484abc948daa525516464785009d1e7a63ffd6012b9e85b56477acc3e624`, `7b47ed28e84437aee64ffe9770d315c1b984135105f7f608a8b9579517bc0695`, `526ab39d1f56732e4e926715aaa797feb13b1ae86882ec570a4d292e7fdc3699`, `a98e04dec3a7fe507eb30c72da808bad60bc14d9d80f9770ec99c438faa85a1a` _(+16 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
