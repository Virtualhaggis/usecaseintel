# [CRIT] AI Agent Uncovers 21 Zero-Days in FFmpeg; Chrome Patches Record 429 Bugs

**Source:** The Hacker News
**Published:** 2026-06-06
**Article:** https://thehackernews.com/2026/06/ai-agent-uncovers-21-zero-days-in.html

## Threat Profile

AI Agent Uncovers 21 Zero-Days in FFmpeg; Chrome Patches Record 429 Bugs 
 Swati Khandelwal  Jun 06, 2026 Vulnerability / Endpoint Security 
Two things landed within days of each other this week. A security startup reported 21 previously unknown vulnerabilities in FFmpeg, the media library inside almost everything that touches video, all of them found by an autonomous AI agent.
The same week, Google shipped Chrome 149 with patches for 429 security bugs, the most ever in a single release.
Only …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-39210`
- **CVE:** `CVE-2026-39211`
- **CVE:** `CVE-2026-39212`
- **CVE:** `CVE-2026-39213`
- **CVE:** `CVE-2026-39214`
- **CVE:** `CVE-2026-39215`
- **CVE:** `CVE-2026-39216`
- **CVE:** `CVE-2026-39217`
- **CVE:** `CVE-2026-39218`
- **CVE:** `CVE-2026-10881`
- **CVE:** `CVE-2026-10882`
- **CVE:** `CVE-2026-10883`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1588.006** — Obtain Capabilities: Vulnerabilities
- **T1203** — Exploitation for Client Execution
- **T1189** — Drive-by Compromise

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable FFmpeg versions exposed to CVE-2026-39210 through CVE-2026-39218

`UC_78_6` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-39210","CVE-2026-39211","CVE-2026-39212","CVE-2026-39213","CVE-2026-39214","CVE-2026-39215","CVE-2026-39216","CVE-2026-39217","CVE-2026-39218") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | sort - lastSeen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId in ("CVE-2026-39210","CVE-2026-39211","CVE-2026-39212","CVE-2026-39213","CVE-2026-39214","CVE-2026-39215","CVE-2026-39216","CVE-2026-39217","CVE-2026-39218")
   or (SoftwareName has "ffmpeg" and VulnerabilitySeverityLevel in ("High","Critical"))
| join kind=leftouter (DeviceTvmSoftwareInventory | where SoftwareName has "ffmpeg" | summarize InstalledVersions = make_set(SoftwareVersion) by DeviceId) on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, InstalledVersions
| order by VulnerabilitySeverityLevel asc, DeviceName asc
```

### FFmpeg invoked against untrusted RTSP / AV1-over-RTP sources

`UC_78_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name IN ("ffmpeg.exe","ffprobe.exe","ffplay.exe","ffmpeg","ffprobe","ffplay")) AND (Processes.process="*rtsp://*" OR Processes.process="*-c:v libdav1d*" OR Processes.process="*-c:v av1*" OR Processes.process="*libaom-av1*" OR Processes.process="*av1_*" OR Processes.process="*-f rtp*" OR Processes.process="*mpegts*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | rex field=cmdlines "(?<stream_url>rtsp://[^ \"]+)" | sort - lastSeen
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ffmpeg.exe","ffprobe.exe","ffplay.exe","ffmpeg","ffprobe","ffplay")
| where ProcessCommandLine has_any ("rtsp://","-c:v libdav1d","-c:v av1","libaom-av1","av1_","-f rtp","mpegts")
| extend StreamUrl = extract(@"(?i)(rtsp://[^\s\"]+)", 1, ProcessCommandLine)
| extend StreamHost = extract(@"(?i)rtsp://(?:[^@/\s]+@)?([^/:\s]+)", 1, ProcessCommandLine)
| extend Av1Flag = ProcessCommandLine has_any ("libdav1d","libaom-av1","av1_","-c:v av1")
| extend RtpFlag = ProcessCommandLine has_any ("-f rtp","-f mpegts","-rtsp_transport")
| where StreamUrl != "" or Av1Flag or RtpFlag
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, StreamUrl, StreamHost, Av1Flag, RtpFlag, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### Chrome installs below 149.0.7827.53 carrying CVE-2026-10881 sandbox-escape exposure

`UC_78_8` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2026-10881" OR (Vulnerabilities.signature="Google Chrome" AND Vulnerabilities.severity IN ("high","critical")) by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | sort - lastSeen
```

**Defender KQL:**
```kql
let FixedBuild = "149.0.7827.53";
DeviceTvmSoftwareInventory
| where Timestamp > ago(7d)
| where SoftwareVendor in~ ("google","microsoft","brave software","opera") and SoftwareName has_any ("chrome","edge","brave","opera","chromium")
| extend BuildParts = split(SoftwareVersion, ".")
| extend Major = toint(BuildParts[0]), Minor = toint(BuildParts[1]), Patch = toint(BuildParts[2]), Hotfix = toint(BuildParts[3])
| where (SoftwareName has "chrome" and (Major < 149 or (Major == 149 and Patch < 7827) or (Major == 149 and Patch == 7827 and Hotfix < 53)))
   or (SoftwareName has_any ("edge","brave","opera","chromium") and Major < 149)
| join kind=leftouter (DeviceTvmSoftwareVulnerabilities | where CveId == "CVE-2026-10881") on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, FixedBuild, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by SoftwareName asc, SoftwareVersion asc
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
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
    | where AccountName !endswith "$"
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
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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
  - CVE(s): `CVE-2026-39210`, `CVE-2026-39211`, `CVE-2026-39212`, `CVE-2026-39213`, `CVE-2026-39214`, `CVE-2026-39215`, `CVE-2026-39216`, `CVE-2026-39217` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
