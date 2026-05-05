# [HIGH] Microsoft Defender Mistakenly Flags DigiCert Root Certificates as Malware

**Source:** Cyber Security News
**Published:** 2026-05-03
**Article:** https://cybersecuritynews.com/defender-flags-digicert-root-certificates/

## Threat Profile

Home Cyber Security 
Microsoft Defender Mistakenly Flags DigiCert Root Certificates as Malware 
By Guru Baran 
May 3, 2026 
Microsoft Defender triggered widespread false positive alerts after a faulty security update caused it to flag two legitimate DigiCert root certificates as malicious, potentially disrupting SSL/TLS validation and code-signing operations across enterprise environments worldwide.
A Defender antimalware signature update released around April 30, 2026, introduced a detection la…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43`
- **SHA1:** `DDFB16CD4931C973A2037D3FC83A4D7D775D05E4`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1027** — Obfuscated Files or Information
- **T1553.004** — Subvert Trust Controls: Install Root Certificate
- **T1112** — Modify Registry

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Identify endpoints affected by Defender FP signature 'Trojan:Win32/Cerdigent.A!dha' (DigiCert root cert quarantine)

`UC_19_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Alerts.signature) as signature values(Alerts.user) as user from datamodel=Alerts where Alerts.signature="Trojan:Win32/Cerdigent.A!dha" OR (Alerts.signature="Trojan*Cerdigent*") by Alerts.dest Alerts.vendor Alerts.product | `drop_dm_object_name(Alerts)` | eval firstSeen=strftime(firstSeen,"%Y-%m-%d %H:%M:%S"), lastSeen=strftime(lastSeen,"%Y-%m-%d %H:%M:%S") | sort - lastSeen
```

**Defender KQL:**
```kql
// Scope hunt for the Cerdigent.A!dha false-positive across the estate.
// Joins AlertInfo (rule metadata) with AlertEvidence (per-entity rows)
// to surface every device touched by the bad signature, plus the
// registry key / file evidence that Defender quarantined.
let WindowStart = datetime(2026-04-30T00:00:00Z);  // signature 1.449.424.0 release
let DigiCertThumbs = dynamic(["0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43",
                              "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4"]);
AlertInfo
| where Timestamp > WindowStart
| where Title has "Cerdigent" or Title has "Trojan:Win32/Cerdigent.A!dha"
| join kind=inner (
    AlertEvidence
    | where Timestamp > WindowStart
    | project Timestamp, AlertId, DeviceId, DeviceName, EntityType,
              FileName, FolderPath, SHA1, RegistryKey=tostring(parse_json(AdditionalFields).RegistryKey),
              AccountName, AdditionalFields
  ) on AlertId
| extend HitsDigiCertThumbprint = iif(
    SHA1 in (DigiCertThumbs)
      or tostring(AdditionalFields) has_any (DigiCertThumbs)
      or RegistryKey has_any (DigiCertThumbs), "yes","no")
| summarize FirstAlert=min(Timestamp), LastAlert=max(Timestamp),
            EvidenceTypes=make_set(EntityType),
            ImpactedKeys=make_set_if(RegistryKey, isnotempty(RegistryKey)),
            ImpactedFiles=make_set_if(FileName, isnotempty(FileName)),
            DigiCertHit=max(HitsDigiCertThumbprint)
            by DeviceId, DeviceName, Title, Severity
| order by FirstAlert asc
```

### [LLM] DigiCert root certificate registry key deletion under HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates

`UC_19_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Registry.registry_value_name) as value_name values(Registry.process_name) as process_name values(Registry.user) as user from datamodel=Endpoint.Registry where (Registry.registry_path="*\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43*" OR Registry.registry_path="*\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\DDFB16CD4931C973A2037D3FC83A4D7D775D05E4*") (Registry.action=deleted OR Registry.action=removed OR Registry.action=modified) by Registry.dest Registry.registry_path Registry.action | `drop_dm_object_name(Registry)` | eval firstSeen=strftime(firstSeen,"%Y-%m-%d %H:%M:%S"), lastSeen=strftime(lastSeen,"%Y-%m-%d %H:%M:%S") | sort - lastSeen
```

**Defender KQL:**
```kql
// Find every endpoint that lost a DigiCert root cert key, and check
// whether the same key was subsequently recreated (signature 1.449.430.0
// silent restore). Devices with deletion but no recreation are the
// remediation backlog.
let WindowStart = datetime(2026-04-30T00:00:00Z);
let DigiCertThumbs = dynamic(["0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43",
                              "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4"]);
let Deletions = DeviceRegistryEvents
    | where Timestamp > WindowStart
    | where ActionType in ("RegistryKeyDeleted","RegistryValueDeleted")
    | where RegistryKey has @"\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates"
    | where RegistryKey has_any (DigiCertThumbs)
    | extend Thumbprint = extract(@"([0-9A-Fa-f]{40})", 1, RegistryKey)
    | project DeleteTime=Timestamp, DeviceId, DeviceName, Thumbprint,
              DeletedKey=RegistryKey,
              DeletedBy=InitiatingProcessFileName,
              DeletedByPath=InitiatingProcessFolderPath,
              DeletedByCmd=InitiatingProcessCommandLine;
let Restores = DeviceRegistryEvents
    | where Timestamp > WindowStart
    | where ActionType in ("RegistryKeyCreated","RegistryValueSet")
    | where RegistryKey has @"\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates"
    | where RegistryKey has_any (DigiCertThumbs)
    | extend Thumbprint = extract(@"([0-9A-Fa-f]{40})", 1, RegistryKey)
    | summarize RestoreTime=max(Timestamp),
                RestoredBy=any(InitiatingProcessFileName)
                by DeviceId, Thumbprint;
Deletions
| join kind=leftouter Restores on DeviceId, Thumbprint
| extend RestorationStatus = case(
    isempty(RestoreTime), "NOT_RESTORED",
    RestoreTime > DeleteTime, strcat("RESTORED_AFTER_", datetime_diff('hour', RestoreTime, DeleteTime), "h"),
    "RESTORE_PRECEDES_DELETE")
| project DeleteTime, DeviceName, Thumbprint, DeletedKey,
          DeletedBy, DeletedByPath, DeletedByCmd,
          RestoreTime, RestoredBy, RestorationStatus
| order by RestorationStatus asc, DeleteTime asc
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

### Article-specific behavioural hunt — Microsoft Defender Mistakenly Flags DigiCert Root Certificates as Malware

`UC_19_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Defender Mistakenly Flags DigiCert Root Certificates as Malware ```
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Defender Mistakenly Flags DigiCert Root Certificates as Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43`, `DDFB16CD4931C973A2037D3FC83A4D7D775D05E4`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
